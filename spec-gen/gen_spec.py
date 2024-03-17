import csv
import json
from argparse import ArgumentParser
from pathlib import Path

from find_utils import find_function, find_usage
from gen_utils import (
    OpsType,
    SyzSpec,
    existing_fds,
    find_missing_code,
    find_missing_ioctl,
    gen_getsockopt_prompt,
    gen_setsockopt_prompt,
    gen_sockaddr_prompt,
    gen_sockopt_arg_prompt,
    gen_step0_prompt,
    gen_step1_cmd_prompt,
    gen_step2_prompt,
    gen_step3_prompt,
    gen_step4_prompt,
    get_ioctl_name,
    get_ops_type,
    get_path_name,
    get_unique_name,
    is_booting_dev_files,
    is_existing_filename,
    is_existing_type,
    merge_init_ioctl,
    parse_proto_ops,
    pop_unknown_args,
    pop_unknown_spec,
    pop_unknown_types,
    skip_spec,
    update_spec_dict,
    update_types,
)
from llm_utils import query_gpt4
from loguru import logger
from output_spec import initialize_spec_dict, is_primitive_type, output_spec
from ret_types import RetTypes
from rich import print
from rich.progress import track

MAX_DEPTH = 3
MAX_CMD_TRIES = 10
INCURRED_OPS = set()
OUTPUT_DIR = Path("spec-output")


def gen_answer(prompt: str, prompt_path: Path, answer_path: Path):
    prompt_path.write_text(prompt)
    answer = query_gpt4(prompt)
    if answer is None:
        logger.error(f"[{prompt_path}] Step 1 failed")
        return
    answer_path.write_text(answer)
    return answer


def gen_init(file_path: Path, ops_code, ops_name, prompt_output_path, ops_type):
    open_prompt_path = prompt_output_path / "init-prompt.txt"
    open_output_path = prompt_output_path / "init-output.txt"

    if not open_output_path.exists():
        usage_info = find_usage(ops_name, str(file_path))
        if not usage_info:
            logger.error(f"[{ops_name}] Failed to find usage")
            raise ValueError("Failed to find usage", RetTypes.UNFOUND_ERROR)
        else:
            usage_file_path = usage_info["header"]
            usage_source_code = usage_info["source"]

        open_prompt = gen_step0_prompt(
            file_path,
            ops_code,
            usage_file_path,
            usage_source_code,
            ops_type,
        )
        open_prompt_path.write_text(open_prompt)
        open_answer = query_gpt4(open_prompt)
        open_output_path.write_text(open_answer)
    else:
        open_answer = open_output_path.read_text()

    try:
        open_answer = json.loads(open_answer)
    except json.decoder.JSONDecodeError:
        logger.error(f"[{ops_name}] Failed to decode json")
        raise ValueError("Failed to decode json", RetTypes.LLM_ERROR)

    open_answer["ops_name"] = ops_name

    if ops_type == OpsType.DRIVER:
        if open_answer.get("open") is None:
            logger.error(f"[{ops_name}] Failed to analyze the open")
            raise ValueError("Failed to analyze the open", RetTypes.LLM_ERROR)
        if "filename" not in open_answer["open"]:
            logger.error(f"[{ops_name}] no filename")
            raise ValueError("No filename in answer", RetTypes.LLM_ERROR)
        if "fd_name" not in open_answer["open"]:
            logger.error(f"[{ops_name}] no fd_name")
            raise ValueError("No fd_name in answer", RetTypes.LLM_ERROR)
        return open_answer
    elif ops_type == OpsType.SOCKET:
        if open_answer.get("socket") is None:
            logger.error(f"[{ops_name}] Failed to analyze the socket")
            raise ValueError("Failed to analyze the socket", RetTypes.LLM_ERROR)
        if "domain" not in open_answer["socket"]:
            logger.error(f"[{ops_name}] no filename")
            raise ValueError("No filename in answer", RetTypes.LLM_ERROR)
        return open_answer
    else:
        raise ValueError(f"Unknown ops type {ops_type}")


def gen_types(type_dict: dict, file_path: Path, pop_all_first=False):
    """Generate the spec for the types."""
    for idx in range(MAX_DEPTH + 1):
        if idx == 0 and pop_all_first:
            unknown_types = pop_unknown_types(type_dict, pop_all=True)
        else:
            unknown_types = pop_unknown_types(type_dict)

        if len(unknown_types) == 0:
            break
        for type_name in unknown_types:
            logger.info(f"Type generation for {type_name}")

            type_out_dir = OUTPUT_DIR / "types" / type_name
            type_out_dir.mkdir(exist_ok=True, parents=True)
            type_prompt_path = type_out_dir / "prompt.txt"
            type_answer_path = type_out_dir / "answer.txt"

            if type_answer_path.exists():
                logger.info(f"[{file_path}] Step 3 exists, skip")
                new_type_answer = type_answer_path.read_text()
            else:
                if is_existing_type(type_name):
                    logger.info(f"Existing type: {type_name}")
                    type_dict[type_name] = "EXISTING"
                    continue

                if is_primitive_type(type_name):
                    logger.info(f"Primitive type: {type_name}")
                    type_dict[type_name] = "PRIMITIVE"
                    continue

                found_missing, missing_source_code = find_missing_code(
                    [type_name], [], file_path
                )
                if not found_missing:
                    logger.error(f"Unfound type: {type_name}")
                    type_dict[type_name] = "UNFOUND"
                    continue

                step3_prompt = gen_step3_prompt(
                    file_path,
                    json.dumps({type_name: None}, indent=2),
                    missing_source_code,
                )
                new_type_answer = gen_answer(
                    step3_prompt, type_prompt_path, type_answer_path
                )
            update_types(type_dict, new_type_answer)
    return type_dict


def gen_sockaddr(file_path, bind_name, bind_code):
    bind_unique_name = get_unique_name(bind_name, file_path)
    bind_output_dir = OUTPUT_DIR / "binds" / bind_unique_name
    bind_output_dir.mkdir(exist_ok=True, parents=True)

    prompt_path = bind_output_dir / "sockaddr-prompt.txt"
    answer_path = bind_output_dir / "sockaddr-answer.txt"

    if answer_path.exists():
        logger.info(f"[{file_path}] sockaddr exists, skip")
        answer = answer_path.read_text()
    else:
        prompt = gen_sockaddr_prompt(file_path, bind_code)
        prompt_path.write_text(prompt)
        answer = query_gpt4(prompt)
        if answer is None:
            logger.error(f"[{file_path}] Step 0 failed")
            return
        answer_path.write_text(answer)

    return json.loads(answer)


def gen_ioctl(
    file_path: Path,
    ioctl_name: str,
    ioctl_code: str,
):
    """Generate the spec for the IOCTL handler."""
    ioctl_spec = SyzSpec()

    unique_ioctl_name = get_unique_name(ioctl_name, file_path)
    ioctl_output_path = OUTPUT_DIR / "ioctls" / unique_ioctl_name
    ioctl_output_path.mkdir(exist_ok=True, parents=True)
    # Step 1: generate the step1 prompt
    step1_final_output_path = ioctl_output_path / "step1-final.txt"

    step1_output_path = ioctl_output_path / "step1.txt"
    step1_answer_path = ioctl_output_path / "step1-answer.txt"

    if (
        step1_answer_path.exists()
        and "ret_inference" in step1_answer_path.read_text()
    ):
        logger.info(f"[{file_path}] Step 1 exists, skip")
        step1_answer = step1_answer_path.read_text()
    else:
        usage_code = ioctl_code.splitlines()[0].split("{")[0]
        step1_prompt = gen_step1_cmd_prompt(
            file_path,
            json.dumps(
                {
                    "function": [ioctl_name],
                    "type": [],
                    "cmd_usage": [usage_code],
                    "arg_usage": [usage_code],
                },
                indent=2,
            ),
            ioctl_code,
        )
        step1_answer = gen_answer(
            step1_prompt, step1_output_path, step1_answer_path
        )
    ioctl_spec.add_ioctls(step1_answer)

    if ioctl_spec.ioctl_skip():
        logger.error(f"[{file_path}] Step 1 failed due to no syz-spec")
        # raise ValueError("No syz-spec", RetTypes.LLM_ERROR, 1)
        return

    # Step 1-CMD: Infer the unknown cmd.
    step1_cmd_cnt = 0
    depth = 0
    already_missing = set()
    while depth < MAX_DEPTH or step1_cmd_cnt < MAX_CMD_TRIES:
        unknown_cmd_ioctls = ioctl_spec.pop_unknown_cmd_ioctls()
        if len(unknown_cmd_ioctls) == 0:
            break
        for _, unknown_info_dict in enumerate(unknown_cmd_ioctls):
            missing_funcs = unknown_info_dict["function"]
            missing_func_str = "+".join(sorted(missing_funcs))
            if missing_func_str in already_missing:
                logger.info(
                    f"[{file_path}] Step 1-CMD already miss {missing_func_str}"
                )
                continue
            already_missing.add(missing_func_str)
            # Truncate the missing funcs if too long
            if len(missing_func_str) > 30:
                missing_func_str = missing_func_str[:30] + "==="

            logger.info(
                f"[{file_path}] Step 1: unknown cmd in {missing_func_str}"
            )
            step1_cmd_cnt += 1
            step1_cmd_output_path = (
                ioctl_output_path / f"step1-cmd-{missing_func_str}.txt"
            )
            step1_cmd_answer_path = (
                ioctl_output_path / f"step1-cmd-{missing_func_str}-answer.txt"
            )
            if (
                step1_cmd_answer_path.exists()
                and "ret_inference" in step1_cmd_answer_path.read_text()
            ):
                logger.info(
                    f"[{file_path}] Step 1-CMD {missing_func_str} exists"
                )
                step1_cmd_answer = step1_cmd_answer_path.read_text()
                ioctl_spec.add_ioctls(step1_cmd_answer)
                continue

            found_missing, missing_source_code = find_missing_ioctl(
                unknown_info_dict, file_path, only_func=True
            )
            if not found_missing:
                logger.error(
                    f"[{file_path}] Step 1-CMD for {missing_func_str} failed"
                )
                continue
            step1_cmd_prompt = gen_step1_cmd_prompt(
                file_path,
                json.dumps(unknown_info_dict, indent=2),
                missing_source_code,
            )
            step1_cmd_answer = gen_answer(
                step1_cmd_prompt, step1_cmd_output_path, step1_cmd_answer_path
            )

            ioctl_spec.add_ioctls(step1_cmd_answer)
        depth += 1

    step1_final_output_path.write_text(json.dumps(ioctl_spec.data, indent=2))

    if ioctl_spec.ioctl_skip():
        logger.error(f"[{file_path}] Step 1 failed")
        return
    ioctl_spec.distill_unknown_ioctls()
    if ioctl_spec.ioctl_skip():
        logger.error(f"[{file_path}] Step 1 failed due to all unknown ioctls")
        return

    # Step 2: Infer the unknown arg.
    for depth in range(MAX_DEPTH):
        # Don't skip existing ioctls
        unknown_arg_ioctls = ioctl_spec.pop_unknown_arg_ioctls(
            skip_existing=True
        )
        for cmd_name, cmd_data in unknown_arg_ioctls.items():
            logger.info(f"[{file_path}] Step 2: unknown arg for {cmd_name}")

            step2_output_path = (
                ioctl_output_path / f"step2-{cmd_name}-{depth}.txt"
            )
            step2_answer_path = (
                ioctl_output_path / f"step2-{cmd_name}-{depth}-answer.txt"
            )
            if step2_answer_path.exists():
                logger.info(f"[{file_path}] Step 2 exists, skip")
                step2_answer = step2_answer_path.read_text()
            else:
                found_missing, missing_source_code = find_missing_ioctl(
                    cmd_data["arg_inference"], file_path
                )
                if not found_missing:
                    missing_source_code = ""

                cmd_data_copy = cmd_data.copy()
                cmd_data_copy.pop("ret_inference", None)
                step2_prompt = gen_step2_prompt(
                    file_path,
                    json.dumps({cmd_name: cmd_data_copy}, indent=2),
                    missing_source_code,
                )
                step2_answer = gen_answer(
                    step2_prompt, step2_output_path, step2_answer_path
                )
            answer_dict = json.loads(step2_answer)
            if cmd_name not in answer_dict:
                logger.error(f"[{file_path}] Step 2 failed for {cmd_name}")
                continue
            new_cmd_data = answer_dict[cmd_name]
            new_cmd_data["ret_inference"] = cmd_data["ret_inference"]
            processed_dict = {
                "ioctls": {
                    cmd_name: new_cmd_data,
                },
                "types": answer_dict["types"],
            }
            ioctl_spec.add_ioctls(json.dumps(processed_dict))

    # Step3: Infer the type.
    type_dict = ioctl_spec.data["types"]
    type_dict = gen_types(type_dict, file_path, pop_all_first=True)
    ioctl_spec.data["types"] = type_dict

    # Step4: Infer the return value of the ioctl
    for ioctl_name, ioctl_data in ioctl_spec.data["ioctls"].items():
        if "ret_inference" in ioctl_data:
            logger.info(f"[{file_path}] Step 4: ret_inference for {ioctl_name}")
            ret_inference = ioctl_data["ret_inference"]
            if ret_inference is None:
                continue

            for depth in range(5):
                step4_output_path = (
                    ioctl_output_path / f"step4-{ioctl_name}-{depth}.txt"
                )
                step4_answer_path = (
                    ioctl_output_path / f"step4-{ioctl_name}-{depth}-answer.txt"
                )
                if step4_answer_path.exists():
                    logger.info(f"[{file_path}] Step 4 exists, skip")
                    step4_answer = step4_answer_path.read_text()
                else:
                    found_missing, missing_source_code = find_missing_ioctl(
                        ret_inference, file_path
                    )
                    if not found_missing:
                        break

                    step4_prompt = gen_step4_prompt(
                        file_path,
                        json.dumps({"inference": ret_inference}, indent=2),
                        missing_source_code,
                    )
                    step4_answer = gen_answer(
                        step4_prompt, step4_output_path, step4_answer_path
                    )
                answer_dict = json.loads(step4_answer)
                if "fops" not in answer_dict:
                    logger.error(
                        f"[{file_path}] Step 4 failed for {ioctl_name}"
                    )
                    continue
                fops = answer_dict["fops"]
                if fops is None:
                    break
                if fops == "UNKNOWN":
                    if "inference" in answer_dict:
                        ret_inference = answer_dict["inference"]
                        continue
                    else:
                        logger.error(
                            f"[{file_path}] Step 4 failed {ioctl_name} due to no inference"  # noqa
                        )
                        break
                else:
                    ioctl_spec.data["ioctls"][ioctl_name]["fops"] = fops
                    global INCURRED_OPS
                    INCURRED_OPS.add(fops)
                    break

    spec_answer_path = ioctl_output_path / "spec.json"
    spec_answer_path.write_text(json.dumps(ioctl_spec.data, indent=2))
    return ioctl_spec.data


def gen_spec_recursive(
    file_path: Path,
    f_name: str,
    f_code: str,
    key_name: str = "setsockopt",
    arg_name: str = "val",
    prompt_gen_func=gen_step1_cmd_prompt,
    prompt_gen_arg_func=gen_step2_prompt,
    # is_unknown_arg_func=None,
):
    """Generate the spec for the IOCTL handler."""
    spec = {
        key_name: {},
        "unknown": [],
        "types": {},
    }

    unique_name = get_unique_name(f_name, file_path)
    output_path = OUTPUT_DIR / key_name / unique_name
    output_path.mkdir(exist_ok=True, parents=True)

    step1_output_path = output_path / "step1.txt"
    step1_answer_path = output_path / "step1-answer.txt"

    if step1_answer_path.exists():
        logger.info(f"[{f_name}] Step 1 exists, skip")
        step1_answer = step1_answer_path.read_text()
    else:
        step1_prompt = prompt_gen_func(
            file_path,
            json.dumps(
                {
                    "function": [f_name],
                    "type": [],
                },
                indent=2,
            ),
            f_code,
        )
        step1_answer = gen_answer(
            step1_prompt, step1_output_path, step1_answer_path
        )
    update_spec_dict(spec, step1_answer)

    if skip_spec(spec, key_name):
        logger.error(f"[{f_name}] Step 1 failed due to no spec")
        return

    # Step 1-CMD: Infer the unknown cmd.
    step1_cmd_cnt = 0
    depth = 0
    already_missing = set()
    while depth < MAX_DEPTH or step1_cmd_cnt < MAX_CMD_TRIES:
        unknown_arg_specs = pop_unknown_spec(spec, key_name)
        if len(unknown_arg_specs) == 0:
            break
        for _, unknown_info_dict in enumerate(unknown_arg_specs):
            missing_funcs = unknown_info_dict["function"]
            missing_func_str = "+".join(sorted(missing_funcs))
            if missing_func_str in already_missing:
                logger.info(
                    f"[{f_name}] Step 1-CMD already miss {missing_func_str}"
                )
                continue
            already_missing.add(missing_func_str)
            # Truncate the missing funcs if too long
            if len(missing_func_str) > 30:
                missing_func_str = missing_func_str[:30] + "==="
            logger.info(f"[{f_name}] Step 1: unknown in {missing_func_str}")
            step1_cmd_cnt += 1
            step1_cmd_output_path = (
                output_path / f"step1-cmd-{missing_func_str}.txt"
            )
            step1_cmd_answer_path = (
                output_path / f"step1-cmd-{missing_func_str}-answer.txt"
            )
            if step1_cmd_answer_path.exists():
                logger.info(f"[{f_name}] Step 1-CMD {missing_func_str} exists")
                step1_cmd_answer = step1_cmd_answer_path.read_text()
                update_spec_dict(spec, step1_cmd_answer)
            else:
                found_missing, missing_source_code = find_missing_code(
                    unknown_info_dict["function"], [], file_path
                )
                if not found_missing:
                    logger.error(
                        f"[{f_name}] Step 1-CMD for {missing_func_str} failed"
                    )
                    continue
                step1_cmd_prompt = prompt_gen_func(
                    file_path,
                    json.dumps(unknown_info_dict, indent=2),
                    missing_source_code,
                )
                step1_cmd_answer = gen_answer(
                    step1_cmd_prompt,
                    step1_cmd_output_path,
                    step1_cmd_answer_path,
                )
                update_spec_dict(spec, step1_cmd_answer)
        depth += 1

    unknown_arg_specs = pop_unknown_spec(spec, key_name)
    spec[f"{key_name}_unknown"] = unknown_arg_specs
    if skip_spec(spec, key_name):
        logger.error(f"[{f_name}] Step 1 failed")
        return

    # Step 2: Infer the unknown arg.
    for depth in range(MAX_DEPTH):
        unknown_args = pop_unknown_args(spec, key_name, arg_name)
        for cmd_name, cmd_data in unknown_args.items():
            logger.info(f"[{f_name}] Step 2: unknown arg for {cmd_name}")

            step2_output_path = output_path / f"step2-{cmd_name}-{depth}.txt"
            step2_answer_path = (
                output_path / f"step2-{cmd_name}-{depth}-answer.txt"
            )
            if step2_answer_path.exists():
                logger.info(f"[{f_name}] Step 2 exists, skip")
                step2_answer = step2_answer_path.read_text()
            else:
                found_missing, missing_source_code = find_missing_ioctl(
                    cmd_data[f"{arg_name}_inference"], file_path
                )
                if not found_missing:
                    missing_source_code = ""

                step2_prompt = prompt_gen_arg_func(
                    file_path,
                    json.dumps({cmd_name: cmd_data}, indent=2),
                    missing_source_code,
                )
                step2_answer = gen_answer(
                    step2_prompt, step2_output_path, step2_answer_path
                )
            answer_dict = json.loads(step2_answer)
            if cmd_name not in answer_dict:
                logger.error(f"[{key_name}] Step 2 failed for {cmd_name}")
                continue
            processed_dict = {
                key_name: {
                    cmd_name: answer_dict[cmd_name],
                },
                "types": answer_dict["types"],
            }
            update_spec_dict(spec, json.dumps(processed_dict))
        # Step3: Infer the type.
    type_dict = spec["types"]
    type_dict = gen_types(type_dict, file_path, pop_all_first=True)
    spec["types"] = type_dict

    spec_answer_path = output_path / "spec.json"
    spec_answer_path.write_text(json.dumps(spec, indent=2))
    return spec


def gen_socket_spec(ops_name, ops_path, ops_code):
    statistics = {
        "ops_name": ops_name,
        "path": get_path_name(ops_path, replace_slash=False),
        "exists_filename": None,
        "exists_fd": None,
        "result": None,
        "num_new_ioctls": 0,
        "num_existing_ioctls": 0,
        "num_new_opts": 0,
        "num_existing_opts": 0,
        "in_dev": None,
        "filename": "",
        "fd_name": "",
    }

    # Generate the initialization descriptions
    gen_path = OUTPUT_DIR / "sockets" / get_unique_name(ops_name, ops_path)
    gen_path.mkdir(exist_ok=True, parents=True)
    try:
        init_answer = gen_init(
            ops_path,
            ops_code,
            ops_name,
            gen_path,
            OpsType.SOCKET,
        )
    except ValueError as e:
        ret_type: RetTypes = e.args[1]
        statistics["result"] = f"Open Failed, {ret_type.name}"
        return statistics

    proto_ops = parse_proto_ops(ops_code)
    if not proto_ops:
        statistics["result"] = "parse proto ops failed"
        return statistics

    if "bind" in proto_ops:
        bind_name = proto_ops["bind"]
        bind_info = find_function(bind_name, ops_path)
        sock_path = Path(bind_info["header"])
        bind_code = bind_info["source"]

        bind_dict = gen_sockaddr(sock_path, bind_name, bind_code)
        init_answer = merge_init_ioctl(init_answer, bind_dict)
    elif "connect" in proto_ops:
        connect_name = proto_ops["connect"]
        connect_info = find_function(connect_name, ops_path)
        sock_path = Path(connect_info["header"])
        connect_code = connect_info["source"]

        connect_dict = gen_sockaddr(sock_path, connect_name, connect_code)
        init_answer = merge_init_ioctl(init_answer, connect_dict)
    else:
        statistics["result"] = "no bind or connect"
        return statistics

    type_dict = init_answer["types"]
    type_dict = gen_types(type_dict, sock_path)
    init_answer["types"] = type_dict

    if "ioctl" in proto_ops and proto_ops["ioctl"] != "sock_no_ioctl":
        ioctl_name = proto_ops["ioctl"]
        ioctl_info = find_function(ioctl_name, ops_path)
        ioctl_path = Path(ioctl_info["header"])
        ioctl_code = ioctl_info["source"]

        ioctl_dict = gen_ioctl(
            ioctl_path,
            ioctl_name,
            ioctl_code,
        )
        if ioctl_dict and "ioctls" in ioctl_dict:
            statistics["num_new_ioctls"] = len(ioctl_dict["ioctls"])
            statistics["num_existing_ioctls"] = len(
                ioctl_dict["existing_ioctls"]
            )
        init_answer = merge_init_ioctl(init_answer, ioctl_dict)

    if "setsockopt" in proto_ops:
        setsockopt_name = proto_ops["setsockopt"]
        setsockopt_info = find_function(setsockopt_name, ops_path)
        setsockopt_path = Path(setsockopt_info["header"])
        setsockopt_code = setsockopt_info["source"]

        setsockopt_dict = gen_spec_recursive(
            setsockopt_path,
            setsockopt_name,
            setsockopt_code,
            key_name="setsockopt",
            arg_name="val",
            prompt_gen_func=gen_setsockopt_prompt,
            prompt_gen_arg_func=gen_sockopt_arg_prompt,
        )
        if setsockopt_dict and "setsockopt" in setsockopt_dict:
            statistics["num_new_opts"] += len(setsockopt_dict["setsockopt"])
            statistics["num_existing_opts"] += len(
                setsockopt_dict["existing_setsockopt"]
            )
        init_answer = merge_init_ioctl(init_answer, setsockopt_dict)

    if "getsockopt" in proto_ops:
        getsockopt_name = proto_ops["getsockopt"]
        getsockopt_info = find_function(getsockopt_name, ops_path)
        getsockopt_path = Path(getsockopt_info["header"])
        getsockopt_code = getsockopt_info["source"]

        getsockopt_dict = gen_spec_recursive(
            getsockopt_path,
            getsockopt_name,
            getsockopt_code,
            key_name="getsockopt",
            arg_name="val",
            prompt_gen_func=gen_getsockopt_prompt,
            prompt_gen_arg_func=gen_sockopt_arg_prompt,
        )
        if getsockopt_dict and "getsockopt" in getsockopt_dict:
            statistics["num_new_opts"] += len(getsockopt_dict["getsockopt"])
            statistics["num_existing_opts"] += len(
                getsockopt_dict["existing_getsockopt"]
            )
        init_answer = merge_init_ioctl(init_answer, getsockopt_dict)

    init_answer["proto_ops"] = proto_ops
    init_answer["path"] = str(ops_path)
    init_answer["ops_name"] = ops_name

    initialize_spec_dict(init_answer, use_ops_name=False)

    unique_ops_name = get_unique_name(ops_name, ops_path)
    (gen_path / "spec.json").write_text(json.dumps(init_answer, indent=2))
    overall_socket_dir = OUTPUT_DIR / "_generated_sockets"
    overall_socket_dir.mkdir(exist_ok=True, parents=True)
    (overall_socket_dir / f"{unique_ops_name}.json").write_text(
        json.dumps(init_answer, indent=2)
    )
    # General Output
    output_dir = OUTPUT_DIR / "_generated"
    output_dir.mkdir(exist_ok=True, parents=True)
    (output_dir / f"{unique_ops_name}.json").write_text(
        json.dumps(init_answer, indent=2)
    )
    (output_dir / f"{unique_ops_name}.txt").write_text(output_spec(init_answer))
    statistics["result"] = "success"
    return statistics


def gen_driver_spec(ops_name, ops_path, ops_code, output_dir_name="drivers"):
    statistics = {
        "ops_name": ops_name,
        "path": get_path_name(ops_path, replace_slash=False),
        "ioctl_name": "",
        "ioctl_path": "",
        "exists_filename": None,
        "exists_fd": None,
        "result": None,
        "num_new_ioctls": 0,
        "num_existing_ioctls": 0,
        "in_dev": None,
        "filename": "",
        "fd_name": "",
    }

    # Generate the initialization descriptions
    gen_path = (
        OUTPUT_DIR / output_dir_name / get_unique_name(ops_name, ops_path)
    )
    gen_path.mkdir(exist_ok=True, parents=True)
    try:
        open_answer = gen_init(
            ops_path,
            ops_code,
            ops_name,
            gen_path,
            OpsType.DRIVER,
        )
    except ValueError as e:
        ret_type: RetTypes = e.args[1]
        statistics["result"] = f"Open Failed, {ret_type.name}"
        return statistics

    open_answer["path"] = str(ops_path)
    exists_filename = is_existing_filename(open_answer["open"]["filename"])
    exists_fd = open_answer["open"]["fd_name"] in existing_fds
    exists_filename_in_stat = ""
    if exists_filename == "anno":
        exists_filename_in_stat = "anno"
    elif exists_filename:
        exists_filename_in_stat = "Y"
    else:
        exists_filename_in_stat = "N"
    statistics["exists_filename"] = exists_filename_in_stat
    statistics["exists_fd"] = "Y" if exists_fd else "N"
    statistics["filename"] = open_answer["open"]["filename"]
    statistics["fd_name"] = open_answer["open"]["fd_name"]

    dev_filename: str = open_answer["open"]["filename"]
    in_dev = is_booting_dev_files(dev_filename)

    if not dev_filename.startswith("/") or (
        dev_filename.startswith("/dev") and not in_dev
    ):
        logger.error(f"[{ops_name}] skip due to not absolute path")
        statistics["result"] = "skip"
        statistics["in_dev"] = "N"
        return statistics

    statistics["in_dev"] = "Y"

    # Prepare the IOCTL
    ioctl_name = get_ioctl_name(ops_code)
    if not ioctl_name:
        logger.error(f"[{ops_name}] Failed to get ioctl name")
        statistics["result"] = "no ioctl name"
        return statistics
    statistics["ioctl_name"] = ioctl_name

    ioctl_info = find_function(ioctl_name, ops_path)
    if not ioctl_info:
        logger.error(f"[{ops_name}] Failed to find ioctl")
        statistics["result"] = "failed no ioctl"
        return statistics
    ioctl_path = Path(ioctl_info["header"])
    ioctl_code = ioctl_info["source"]
    statistics["ioctl_path"] = str(ioctl_path)

    ioctl_dict = gen_ioctl(
        ioctl_path,
        ioctl_name,
        ioctl_code,
    )
    if not ioctl_dict:
        statistics["result"] = "failed no spec"
        logger.error(f"[{ops_name}] Failed")
        return statistics
    else:
        if len(ioctl_dict["ioctls"]) == 0:
            statistics["result"] = "failed no ioctl"
            statistics["num_new_ioctls"] = 0
            statistics["num_existing_ioctls"] = len(
                ioctl_dict["existing_ioctls"]
            )

            logger.error(f"[{ops_name}] No ioctls")
            return statistics
        statistics["result"] = "success"
        statistics["num_new_ioctls"] = len(ioctl_dict["ioctls"])
        statistics["num_existing_ioctls"] = len(ioctl_dict["existing_ioctls"])

        ret = merge_init_ioctl(open_answer, ioctl_dict)
        logger.info(f"[{ops_name}] Success")

        initialize_spec_dict(ret)
        (gen_path / "spec.json").write_text(json.dumps(ret, indent=2))
        unique_ops_name = get_unique_name(ops_name, ops_path)

        generated_spec_path = OUTPUT_DIR / "_generated"
        generated_spec_path.mkdir(exist_ok=True, parents=True)
        (generated_spec_path / f"{unique_ops_name}.json").write_text(
            json.dumps(ret, indent=2)
        )
        (generated_spec_path / f"{unique_ops_name}.txt").write_text(
            output_spec(ret)
        )
        all_spec_path = OUTPUT_DIR / f"_generated_{output_dir_name}"
        all_spec_path.mkdir(exist_ok=True, parents=True)
        (all_spec_path / f"{unique_ops_name}.json").write_text(
            json.dumps(ret, indent=2)
        )
    return statistics


def output_results(gen_results, output_dir, suffix=None):
    for ops_type, result in gen_results.items():
        type_name = ops_type.name.lower()
        if suffix:
            type_name += f"-{suffix}"

        logger.info(f"{type_name}: {len(result)}")
        if len(result) == 0:
            continue
        result_path = output_dir / f"results-{type_name}.csv"
        with open(result_path, "w") as f:
            keys = list(list(result[0].keys()))
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for data in result:
                writer.writerow(data)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "-d",
        "--data",
        type=str,
        default="ioctl.json",
        help="path to the data file of ioctl functions",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="spec-output",
        help="path to the output directory",
    )
    parser.add_argument(
        "-n",
        "--num",
        type=int,
        default=1,
        help="number of spec to generate",
    )
    parser.add_argument(
        "--debug-file",
        type=str,
        default=None,
        help="path to the debug file",
    )
    args = parser.parse_args()

    json_path = Path(args.data)
    global OUTPUT_DIR
    OUTPUT_DIR = Path(args.output)
    OUTPUT_DIR.mkdir(exist_ok=True)

    log_path = Path("log")
    log_path.mkdir(exist_ok=True)

    idx = 0
    debug_file = args.debug_file
    ops_handler_data = json.loads(json_path.read_text())

    logger.info(f"num of ops: {len(ops_handler_data)}")

    generated_ops = set()
    results = {
        OpsType.DRIVER: [],
        OpsType.SOCKET: [],
        OpsType.FS: [],
        OpsType.VIRT: [],
    }
    for ops_name, ops_data in track(ops_handler_data.items()):
        if idx >= args.num:
            break
        if debug_file and ops_name != debug_file:
            # NOTE: Now it is the name of ops handler
            continue

        for ops_path, ops_code in ops_data.items():
            ops_type = get_ops_type(ops_path, ops_code)

            ops_path = Path(ops_path)
            if ops_type in [OpsType.FS, OpsType.VIRT]:
                logger.info(f"[{ops_name}] Generating fs/virt spec")
                statistics = gen_driver_spec(
                    ops_name, ops_path, ops_code, "fsvt"
                )
            elif ops_type == OpsType.DRIVER:
                logger.info(f"[{ops_name}] Generating driver spec")
                statistics = gen_driver_spec(
                    ops_name,
                    ops_path,
                    ops_code,
                )
            elif ops_type == OpsType.SOCKET:
                logger.info(f"[{ops_name}] Generating socket spec")
                statistics = gen_socket_spec(
                    ops_name,
                    ops_path,
                    ops_code,
                )
            else:
                raise ValueError(f"Unknown ops type {ops_type}")
            idx += 1
            generated_ops.add(ops_name)
            results[ops_type].append(statistics)

    incurred_results = {
        OpsType.DRIVER: [],
        OpsType.SOCKET: [],
        OpsType.FS: [],
        OpsType.VIRT: [],
    }
    # Process with the newly incurred ops
    for ops_name in INCURRED_OPS.copy():
        logger.info(f"Processing incurred ops: {ops_name}")
        if ops_name not in ops_handler_data:
            logger.error(f"Ops name {ops_name} not found")
            continue
        if ops_name in generated_ops:
            logger.info(f"Ops name {ops_name} already generated")
            continue
        ops_data = ops_handler_data[ops_name]

        for ops_path, ops_code in ops_data.items():
            ops_type = get_ops_type(ops_path, ops_code)
            print(ops_type)
            ops_path = Path(ops_path)
            path_name = get_path_name(ops_path, replace_slash=False)
            path_name = path_name.split(":")[0]
            if ops_type in [OpsType.DRIVER, OpsType.VIRT, OpsType.FS]:
                logger.info(f"[{ops_name}] Generating driver spec")
                statistics = gen_driver_spec(
                    ops_name,
                    ops_path,
                    ops_code,
                )
            elif ops_type == OpsType.SOCKET:
                logger.info(f"[{ops_name}] Generating socket spec")
                statistics = gen_socket_spec(
                    ops_name,
                    ops_path,
                    ops_code,
                )
            else:
                raise ValueError(f"Unknown ops type {ops_type}")
            idx += 1
            incurred_results[ops_type].append(statistics)

    # Output the results
    output_results(results, OUTPUT_DIR)
    # Output the incurred results
    output_results(incurred_results, OUTPUT_DIR, "incurred")


if __name__ == "__main__":
    main()
