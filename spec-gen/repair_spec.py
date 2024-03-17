import re
import json
from pathlib import Path
from loguru import logger
from collections import defaultdict
from find_utils import find_type
from llm_utils import query_gpt4
from output_spec import SYSCALL_SPEC_KEY, INIT_SYSCALL_KEY

REPAIR_TEMPLATE_PATH = (
    Path(__file__).parent / "prompt_template" / "step-repair-struct.txt"
)


def repair(
    spec_dict: dict,
    stdout: str,
    spec_output_name: str,
    lines: list,
    idx: int,
    intermediate_path: Path,
):
    """
    Repair the spec using the stdout from the evaluation.
    """
    output_path = Path(intermediate_path) / spec_output_name
    output_path.mkdir(parents=True, exist_ok=True)
    unsupported_pattern = re.compile(
        "([_A-Za-z0-9]+) is unsupported on all arches"
    )
    error_pattern = re.compile(
        f"sys/linux/{spec_output_name}.txt:([0-9]+):([0-9]+): (.+)"
    )

    unsupported = unsupported_pattern.findall(stdout)
    errors = error_pattern.findall(stdout)

    if len(unsupported) == 0 and len(errors) == 0:
        return False

    error_syscall = defaultdict(list)
    error_types = defaultdict(list)
    # Remove the unsupported spec
    unsupported_spec = {}
    init_syscalls = spec_dict[INIT_SYSCALL_KEY]
    for syscall_name, syscall_spec in (
        spec_dict[SYSCALL_SPEC_KEY].copy().items()
    ):
        for unsupport in unsupported:
            pattern = rf"\b{unsupport}\b"
            if re.search(pattern, syscall_spec):
                if unsupport.isupper() and syscall_name not in init_syscalls:
                    unsupported_spec[syscall_name] = syscall_spec
                    spec_dict[SYSCALL_SPEC_KEY].pop(syscall_name)
                else:
                    error_str = f"{unsupport} is unsupported on all arches"
                    error_syscall[syscall_name].append(error_str)

    # Remaining unsupported are in the types, try to collect them
    for typename, type_def in spec_dict["types"].copy().items():
        for unsupport in unsupported.copy():
            # Check whether the unsupport single word is in the type_def
            if re.search(rf"\b{unsupport}\b", type_def):
                error_str = f"{unsupport} is unsupported on all arches"
                error_types[typename].append(error_str)

    # Find the errors in the spec
    for lineno, _, error in errors:
        lineno = int(lineno)
        line = lines[lineno - 1]
        for syscall, syscall_spec in spec_dict[SYSCALL_SPEC_KEY].items():
            if line in syscall_spec:
                error_syscall[syscall].append(error)
                break
        for typename, type_def in spec_dict["types"].items():
            if line in type_def:
                error_types[typename].append(error)
                break

    for syscall in error_syscall:
        error_syscall[syscall] = list(set(error_syscall[syscall]))
        gen_repair(
            syscall,
            error_syscall[syscall],
            spec_dict,
            output_path,
            idx,
            "syscall",
        )
    for type_name in error_types:
        error_types[type_name] = list(set(error_types[type_name]))
        gen_repair(
            type_name,
            error_types[type_name],
            spec_dict,
            output_path,
            idx,
            "type",
        )

    (output_path / f"{spec_output_name}-{idx}.json").write_text(
        json.dumps(spec_dict, indent=2)
    )
    return True


def gen_repair(
    name, error_list, spec_dict, output_path: Path, idx, kind="type"
):
    source = ""
    if kind == "type":
        res = find_type(name, spec_dict["path"])
        if res is not None:
            source = res["source"]
        desc = spec_dict["types"][name]
    elif kind == "syscall":
        desc = spec_dict[SYSCALL_SPEC_KEY][name]
    else:
        desc = spec_dict[kind][name]

    error_str = "\n".join(error_list)
    repair_prompt = REPAIR_TEMPLATE_PATH.read_text()
    repair_prompt = (
        repair_prompt.replace("NAME_PLACEHOLDER", name)
        .replace("DESCRIPTION_PLACEHOLDER", desc)
        .replace("ERROR_PLACEHOLDER", error_str)
        .replace("SOURCE_PLACEHOLDER", source)
    )
    (output_path / f"{name}-{idx}.txt").write_text(repair_prompt)
    answer = query_gpt4(repair_prompt)
    if answer is None:
        logger.error(f"[{name}] Repair failed")
        return
    (output_path / f"{name}-{idx}-answer.txt").write_text(answer)
    try:
        answer_dict = json.loads(answer)
    except json.JSONDecodeError:
        logger.error(f"[{name}] Repair failed")
        return

    if kind == "type":
        if "types" not in answer_dict:
            logger.error(f"[{name}] Repair failed")
            return
        spec_dict["types"].pop(name)
        for type_name, type_def in answer_dict["types"].items():
            spec_dict["types"][type_name] = type_def
    elif kind == "syscall":
        if "syscalls" in answer_dict:
            spec_dict[SYSCALL_SPEC_KEY][name] = ""

            if name not in answer_dict["syscalls"]:
                logger.error(f"[{name}] Repair failed")
                return
            for syscall_name, syscall_spec in answer_dict["syscalls"].items():
                spec_dict[SYSCALL_SPEC_KEY][syscall_name] = syscall_spec
        if "types" in answer_dict:
            for type_name, type_def in answer_dict["types"].items():
                spec_dict["types"][type_name] = type_def
    return True
