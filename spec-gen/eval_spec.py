import json
import re
import subprocess as sp
from argparse import ArgumentParser
from pathlib import Path

import yaml
from gen_utils import is_existing_type
from loguru import logger
from output_spec import (
    PREFIX,
    SYSCALL_SPEC_KEY,
    enable_skip_existing,
    is_primitive_type,
    output_spec,
)
from repair_spec import repair

EVAL_PATH_ROOT = Path(__file__).parent.parent / "spec-eval"
REPAIR_STEP = None
TEMPLATE = "template-valid.cfg"
MERGE_STEP = 5


def update_spec(spec_dict: dict):
    spec_str = ""
    if SYSCALL_SPEC_KEY in spec_dict:
        spec_str = "\n".join(spec_dict[SYSCALL_SPEC_KEY].values())
    else:
        raise ValueError("No syscall spec found")

    # Find the types are in the spec of syscalls
    current_types = spec_dict["types"].copy()
    used_types = {}
    used_type_str = ""
    for typename, type_def in current_types.copy().items():
        if not isinstance(type_def, str):
            continue
        # Whether the single word type name is in the spec_str
        if re.search(rf"\b{typename}\b", spec_str):
            used_types[typename] = type_def
            current_types.pop(typename)
            used_type_str += type_def + "\n"

    has_new = True
    while has_new:
        has_new = False
        for typename, type_def in current_types.copy().items():
            if re.search(rf"\b{typename}\b", used_type_str):
                used_types[typename] = type_def
                current_types.pop(typename)
                used_type_str += type_def + "\n"
                has_new = True

    for typename in used_types.copy():
        used_types[typename] = used_types[typename].replace(";\n", "\n")
        if used_types[typename].startswith("struct "):
            used_types[typename] = used_types[typename][len("struct ") :]
        if used_types[typename].startswith("union "):
            used_types[typename] = used_types[typename][len("union ") :]

    ignored_types = {}
    for typename, type_def in used_types.copy().items():
        if is_existing_type(typename):
            ignored_types[typename] = "EXISTING"
            used_types.pop(typename)
            continue
        if is_primitive_type(typename):
            ignored_types[typename] = "PRIMITIVE"
            used_types.pop(typename)
            continue

        if type_def in ["EXISTING"]:
            ignored_types[typename] = type_def
            used_types.pop(typename)
        elif type_def is None or type_def in [
            "UNFOUND",
            "UNKNOWN",
            "PRIMITIVE",
        ]:
            if typename.isupper():
                ignored_types[typename] = "UNFOUND_MACRO"
                used_types.pop(typename)
            else:
                used_types[typename] = f"type {typename} ptr[in, array[int8]]"
        if is_primitive_type(type_def):
            ignored_types[typename] = "PRIMITIVE"
            used_types[typename] = f"type {typename} {type_def}"

    spec_dict["types"] = used_types
    spec_dict["unused_types"] = current_types
    spec_dict["ignored_types"] = ignored_types


def update_flags(spec_dict: dict):
    # NOTE: Deprecated
    # find all flags
    flags = {}
    for type_name, type_def in spec_dict["types"].items():
        if type_def.startswith(f"{type_name} ="):
            flags[type_name] = type_def
    if "ioctls" in spec_dict:
        for ioctl in spec_dict["ioctls"]:
            arg_spec = spec_dict["ioctls"][ioctl]["arg"]
            if arg_spec.strip().startswith("flags["):
                pattern = re.compile(
                    r"flags\[([a-zA-Z_]+),\s*int[a-zA-Z0-9]+\]"
                )
                flag_res = pattern.findall(arg_spec)
                if len(flag_res) == 0:
                    continue
                flag_name = flag_res[0]
                if flag_name not in flags:
                    arg_spec = "ptr[in, array[int8]]"
                else:
                    arg_spec = pattern.sub(f"flags[{flag_name}]", arg_spec)
            else:
                for flag in flags:
                    # Replace flag_name with flags[flag_name, int32]
                    # But if flags[flag_name, int32] is already in the spec
                    # then don't replace it
                    pattern = re.compile(rf"flags\[{flag},\s*int32\]")
                    if pattern.findall(arg_spec):
                        continue
                    # Only replace the flag_name if it is a standalone word
                    pattern = re.compile(rf"\b{flag}\b")
                    arg_spec = pattern.sub(f"flags[{flag}, int32]", arg_spec)
            spec_dict["ioctls"][ioctl]["arg"] = arg_spec
    for type_name in spec_dict["types"]:
        type_spec = spec_dict["types"][type_name]
        for flag in flags:
            if type_name == flag:
                continue
            pattern = re.compile(rf"flags\[{flag},\s*int[a-zA-Z0-9]+\]")
            if pattern.findall(type_spec):
                continue
            pattern = re.compile(rf"\b{flag}\b")
            type_spec = pattern.sub(f"flags[{flag}, int32]", type_spec)
            spec_dict["types"][type_name] = type_spec


def get_syscalls(spec_dict: dict):
    syscalls = set()
    if "open" in spec_dict:
        syscalls.add(spec_dict["open"]["spec"].split("(")[0])
    if "socket" in spec_dict:
        syscalls.add(spec_dict["socket"]["spec"].split("(")[0])
    if SYSCALL_SPEC_KEY in spec_dict:
        syscalls.update(spec_dict[SYSCALL_SPEC_KEY].keys())

    return list(syscalls)


def generate_config(
    spec_dict: dict, name: str, output_spec_path: Path, timeout=2
):
    """
    Generate a config file for the fuzzer.
    """
    config = {}
    config["name"] = name
    config["timeout"] = timeout
    if spec_dict is None:
        config["runs"] = []
        return config

    this_run = {}
    this_run["name"] = name
    spec_str = str(output_spec_path.relative_to(EVAL_PATH_ROOT.parent))
    this_run["specs"] = [
        [spec_str],
    ]
    this_run["enabled_calls"] = get_syscalls(spec_dict)
    this_run["remove_files"] = []
    config["runs"] = [this_run]
    return config


def run_eval(
    name: str, skip_build_linux=False, skip_run=False, kernel_config=""
):
    """
    Run the spec evaluation.
    """
    logger.info(f"Running {name}")
    run_commands = [
        "python3",
        "run-specs.py",
        "-d",
        name,
        "--custom-template",
        TEMPLATE,
    ]
    if skip_build_linux:
        run_commands.append("--skip-build-linux")
    if skip_run:
        run_commands.append("--skip-run")
    if len(kernel_config) != 0:
        run_commands.append("--use-shared-linux-with-config")
        run_commands.append(kernel_config)
    r = sp.run(
        run_commands,
        cwd=EVAL_PATH_ROOT,
        capture_output=True,
    )
    return r


def evaluate(
    spec_path: Path,
    res_dir: Path,
    unique_name=False,
    output_name="gpt4_eval_j",
    eval_once=False,
    get_config_only=False,
    timeout=2,
):
    logger.info(f"Evaluating {spec_path}")
    spec_path = Path(spec_path)
    spec_dict = json.loads(spec_path.read_text())
    intermediate_dir = res_dir / "intermediate"
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    name = spec_path.stem
    spec_output_name = f"gpt4_{name}_eval"
    has_ioctl = "ioctls" in spec_dict

    output_dir = EVAL_PATH_ROOT / output_name
    output_dir.mkdir(parents=True, exist_ok=True)

    for step in range(REPAIR_STEP + 1):
        update_spec(spec_dict)

        if "open" in spec_dict and has_ioctl and len(spec_dict["ioctls"]) == 0:
            # Only skip the open spec, which is the driver
            logger.warning(f"Empty spec {spec_path.stem}")
            returncode = "Empty"
            break

        output_spec_path = output_dir / f"{spec_output_name}.txt"
        eval_spec_path = output_dir / "gpt4_eval.txt"
        text = output_spec(spec_dict, unique=unique_name)
        output_spec_path.write_text(text)
        eval_spec_path.write_text(text)

        output_spec_json_path = output_dir / f"{spec_output_name}.json"
        output_spec_json_path.write_text(json.dumps(spec_dict, indent=2))

        # Use the same name for the spec
        if eval_once:
            config_dict = generate_config(
                spec_dict, "eval", eval_spec_path, timeout=timeout
            )
        else:
            config_dict = generate_config(
                spec_dict, spec_output_name, output_spec_path, timeout=timeout
            )
        if get_config_only:
            return config_dict

        (output_dir / "config.yaml").write_text(yaml.dump(config_dict))
        r = run_eval(output_name, skip_build_linux=True, skip_run=True)
        returncode = r.returncode
        logger.info(f"Return code: {returncode} for {spec_path.stem}")

        (res_dir / (spec_path.stem + f"-stdout-{step}.txt")).write_text(
            r.stdout.decode()
        )
        (res_dir / (spec_path.stem + f"-stderr-{step}.txt")).write_text(
            r.stderr.decode()
        )

        if returncode == 0 or step == REPAIR_STEP:
            break

        ret = repair(
            spec_dict,
            r.stdout.decode(),
            eval_spec_path.stem,
            text.splitlines(),
            step,
            intermediate_dir,
        )
        if not ret:
            break

    with open(res_dir / "return.txt", "a") as f:
        f.write(f"{spec_path.stem},{returncode}\n")
    logger.info(f"Return code: {returncode} for {spec_path.stem}")
    logger.info(f"Finished evaluating {spec_path.stem}")

    if returncode == 0:
        # Output the correct json
        correct_json_dir = res_dir / "correct-spec"
        correct_json_dir.mkdir(parents=True, exist_ok=True)
        (correct_json_dir / f"{name}.json").write_text(
            json.dumps(spec_dict, indent=2)
        )
        # Output the correct spec
        correct_spec_dir = res_dir / "correct-spec-txt"
        correct_spec_dir.mkdir(parents=True, exist_ok=True)
        (correct_spec_dir / f"{name}.txt").write_text(text)

    # Detete the tmp dir
    # tmp_syzkaller_path = output_dir / f"{name}-tmp"
    # if tmp_syzkaller_path.exists():
    #     shutil.rmtree(tmp_syzkaller_path)


def config_append(config1, config2):
    config1["runs"].extend(config2["runs"])
    return config1


def config_merge(config1, config2):
    config1["runs"][0]["specs"].extend(config2["runs"][0]["specs"])
    return config1


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-s",
        "--spec-path",
        type=str,
        help="Path to the spec, this can be a directory or a json file",
    )
    parser.add_argument(
        "-o",
        "--res-dir",
        type=str,
        default="eval-res",
        help="Path to the result directory",
    )
    parser.add_argument(
        "-r",
        "--repair-step",
        type=int,
        default=5,
        help="The steps of repair",
    )
    parser.add_argument(
        "-u",
        "--unique-name",
        action="store_true",
        help="Whether to use unique name for the spec",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=2,
        help="The timeout for each evaluation",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Whether to parallel the specs without repair",
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Whether to merge all specs without repair",
    )
    parser.add_argument(
        "--output-name",
        type=str,
        default="gpt4-eval",
        help="The name of the output directory",
    )
    parser.add_argument(
        "--template",
        type=str,
        default="template-valid.cfg",
        help="The name of the template config file",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Whether to initialize the output directory",
    )
    parser.add_argument(
        "--kernel-config",
        type=str,
        help="the kernel config used to make shared linux build",
    )
    args = parser.parse_args()

    if args.merge:
        REPAIR_STEP = 0
    else:
        REPAIR_STEP = args.repair_step

    res_dir = Path(args.res_dir)
    res_dir.mkdir(parents=True, exist_ok=True)
    unique_name = args.unique_name
    output_name = args.output_name
    (EVAL_PATH_ROOT / output_name).mkdir(parents=True, exist_ok=True)

    default_config = generate_config(None, "default", None, 1)
    default_config["runs"] = [
        {
            "name": "default",
            "specs": [],
            "enabled_calls": ["openat$*"],
            "remove_files": [],
        }
    ]
    if args.init:
        # Init the output dir
        (EVAL_PATH_ROOT / output_name / "config.yaml").write_text(
            yaml.dump(default_config)
        )
        # Here we use the default config to run the evaluation
        run_eval(
            output_name,
            skip_build_linux=False,
            kernel_config=args.kernel_config,
        )

    TEMPLATE = args.template
    spec_path = Path(args.spec_path)
    if spec_path.is_dir():
        existing = ""
        if (res_dir / "return.txt").exists():
            existing = (res_dir / "return.txt").read_text()

        if args.merge:
            specs = list(spec_path.glob("*.json"))
            enable_skip_existing()

            for spec in specs:
                this_config = evaluate(
                    spec,
                    res_dir,
                    unique_name=True,
                    output_name=output_name,
                    eval_once=False,
                    get_config_only=True,
                )
                config_merge(default_config, this_config)
            default_config["name"] = "merged"
            default_config["timeout"] = args.timeout
            default_config["runs"][0]["enabled_calls"] = [
                f"openat${PREFIX}*",
                f"syz_open_dev${PREFIX}*",
                f"ioctl${PREFIX}*",
                "read*",
                "write*",
                "close*",
                "mount$*",
                "syz_mount_image*",
            ]
            (EVAL_PATH_ROOT / output_name / "config.yaml").write_text(
                yaml.dump(default_config)
            )
            r = run_eval(output_name, kernel_config=args.kernel_config)
        elif args.parallel:
            # Split with 6
            specs = list(spec_path.glob("*.json"))
            specs.sort()

            for i in range(0, len(specs), MERGE_STEP):
                config = generate_config(None, "merged", None, args.timeout)
                end = min(i + MERGE_STEP, len(specs))
                for spec in specs[i:end]:
                    this_config = evaluate(
                        spec,
                        res_dir,
                        unique_name,
                        output_name,
                        get_config_only=True,
                    )
                    config_append(config, this_config)
                (EVAL_PATH_ROOT / output_name / "config.yaml").write_text(
                    yaml.dump(config)
                )
                r = run_eval(output_name, kernel_config=args.kernel_config)
        else:
            for spec in spec_path.glob("*.json"):
                if f"{spec.stem}," in existing:
                    logger.info(f"Already evaluated {spec.stem}")
                    continue
                evaluate(
                    spec,
                    res_dir,
                    unique_name=False,
                    output_name=output_name,
                    eval_once=True,
                    timeout=args.timeout,
                )
    else:
        if spec_path.suffix != ".json":
            raise ValueError("The spec path must be a json file")
        evaluate(
            spec_path,
            res_dir,
            unique_name=False,
            output_name=output_name,
            eval_once=True,
            timeout=args.timeout,
        )
