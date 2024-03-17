import json
import re
from enum import Enum, auto
from pathlib import Path

from find_utils import find_function, find_type
from loguru import logger

PROMPT_TEMPLATE_PATH = Path(__file__).parent / "prompt_template"
STEP0_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "step0_template_open.txt"
STEP1_CMD_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "step1_template_cmd.txt"
STEP2_ARG_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "step2_template_arg.txt"
STEP3_STRUCT_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "step3_template_type.txt"
STEP4_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "step4_template_ret.txt"

STEP0_SOCKET_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "socket" / "step0.txt"
SOCKADDR_TEMPLATE_PATH = PROMPT_TEMPLATE_PATH / "socket" / "step-sockaddr.txt"
SETSOCKOPT_TEMPLATE_PATH = (
    PROMPT_TEMPLATE_PATH / "socket" / "step-setsockopt.txt"
)
GETSOCKOPT_TEMPLATE_PATH = (
    PROMPT_TEMPLATE_PATH / "socket" / "step-getsockopt.txt"
)
SOCKOPT_ARG_TEMPLATE_PATH = (
    PROMPT_TEMPLATE_PATH / "socket" / "step-sockopt-arg.txt"
)

EXISTING_PATH = Path(__file__).parent / "existings"
EXISTING_TYPE_PATH = EXISTING_PATH / "types.txt"
EXISTING_CMD_PATh = EXISTING_PATH / "cmds.txt"
EXISTING_SOCKOPT_PATh = EXISTING_PATH / "sockopt.txt"
EXISTING_FD_PATH = EXISTING_PATH / "fds.txt"
EXISTING_FILENAME_PATH = EXISTING_PATH / "filenames.txt"
DEV_FILES_PATH = EXISTING_PATH / "dev_files.txt"

existing_types = set(EXISTING_TYPE_PATH.read_text().split("\n"))
existing_cmds = set(EXISTING_CMD_PATh.read_text().split("\n"))
existing_sockopts = set(EXISTING_SOCKOPT_PATh.read_text().split("\n"))
existing_fds = set(EXISTING_FD_PATH.read_text().split("\n"))
existing_filenames = set(EXISTING_FILENAME_PATH.read_text().split("\n"))
dev_files = set(DEV_FILES_PATH.read_text().split("\n"))


class OpsType(Enum):
    SOCKET = auto()
    FS = auto()
    VIRT = auto()
    DRIVER = auto()


def get_ops_type(ops_path: str, ops_code: str = None):
    """Get the ops type from the ops name and path."""
    ops_path = str(ops_path)
    if "linux/net" in ops_path:
        if not ops_code:
            return OpsType.SOCKET

        first_code_line = ops_code.splitlines()[0]
        if "proto" in first_code_line:
            return OpsType.SOCKET
        else:
            return OpsType.DRIVER
    if "linux/fs" in ops_path:
        return OpsType.FS
    if "linux/virt" in ops_path:
        return OpsType.VIRT
    return OpsType.DRIVER


def get_path_name(path, replace_slash=True):
    if "linux" in str(path):
        path_str = "".join(str(path).split("linux/")[1:])
    else:
        path_str = str(path).split(" ")[0]

    if replace_slash:
        path_str = path_str.replace("/", "_")
    return path_str


def get_unique_name(name, path):
    path_str = get_path_name(path)
    return name + "#" + path_str


def parse_proto_ops(proto_code: str):
    proto_dict = {}
    pattern_template = r"\.{name}\s*=\s*(\w+)[,\n]"
    ops = [
        "bind",
        "connect",
        "accept",
        "poll",
        "ioctl",
        "sendmsg",
        "recvmsg",
        "setsockopt",
        "getsockopt",
    ]
    for op in ops:
        pattern = pattern_template.format(name=op)
        match = re.search(pattern, proto_code)
        if match:
            proto_dict[op] = match.group(1)
    return proto_dict


def is_skip_path(path_name):
    # _skip_files = ["drivers/usb/", "drivers/atm/", "fs/proc"]
    _skip_files = []
    for skip_file in _skip_files:
        if skip_file in str(path_name):
            return True
    return False


def get_ioctl_name(code: str) -> str:
    """Extract the ioctl function name from the code."""
    pattern = r"\.(unlocked_)?ioctl\s*=\s*(\w+)[,\n]"
    match = re.search(pattern, code)
    if match:
        return match.group(2)
    return ""


def is_skip_usage(usage_code: str):
    if "inode->i_mode" in usage_code:
        return True
    return False


def file_path_to_placeholder(file_path: Path) -> str:
    if "linux" not in str(file_path):
        return "linux/" + str(file_path).split(" ")[0]
    pattern = re.compile(r"linux\w*/(.*)")
    abs_path = file_path.absolute().as_posix()
    file_name = pattern.search(abs_path).group(1)
    return "linux/" + file_name


def gen_sockaddr_prompt(file_path: Path, source_code: str):
    file_path_str = file_path_to_placeholder(file_path)
    sockaddr_template = SOCKADDR_TEMPLATE_PATH.read_text()
    return sockaddr_template.replace("PATH_PLACEHOLDER", file_path_str).replace(
        "SOURCE_CODE_PLACEHOLDER", source_code
    )


def gen_step0_prompt(
    file_path: Path,
    source_code: str,
    used_file_path: str,
    used_code: str,
    ops_type,
):
    if ops_type == OpsType.DRIVER:
        step0_template = STEP0_TEMPLATE_PATH.read_text()
    elif ops_type == OpsType.SOCKET:
        step0_template = STEP0_SOCKET_TEMPLATE_PATH.read_text()
    else:
        raise ValueError(f"Unknown ops type {ops_type} for prompt")

    file_path_str = file_path_to_placeholder(file_path)
    used_path_str = file_path_to_placeholder(Path(used_file_path))
    return (
        step0_template.replace("USED_PATH_PLACEHOLDER", used_path_str)
        .replace("USED_SOURCE_CODE_PLACEHOLDER", used_code)
        .replace("PATH_PLACEHOLDER", file_path_str)
        .replace("SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_step1_cmd_prompt(file_path: Path, partial_spec: str, source_code: str):
    step1_cmd_template = STEP1_CMD_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        step1_cmd_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("PARTIAL_SPEC_PLACEHOLDER", partial_spec)
        .replace("SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_step2_prompt(
    file_path: Path,
    syzkaller_spec: str,
    source_code: str,
):
    step2_template = STEP2_ARG_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        step2_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("INPUT_SYZKALLER_PLACEHOLDER", syzkaller_spec)
        .replace("MISSING_SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_step3_prompt(
    file_path: Path,
    syzkaller_spec: str,
    source_code: str,
):
    step3_template = STEP3_STRUCT_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        step3_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("INPUT_SYZKALLER_PLACEHOLDER", syzkaller_spec)
        .replace("MISSING_SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_step4_prompt(
    file_path: Path,
    inference: str,
    source_code: str,
):
    step4_template = STEP4_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        step4_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("INFERENCE_PLACEHOLDER", inference)
        .replace("MISSING_SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_setsockopt_prompt(file_path: Path, partial_spec: str, source_code: str):
    setsockopt_template = SETSOCKOPT_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        setsockopt_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("PARTIAL_SPEC_PLACEHOLDER", partial_spec)
        .replace("SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_getsockopt_prompt(file_path: Path, partial_spec: str, source_code: str):
    getsockopt_template = GETSOCKOPT_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        getsockopt_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("PARTIAL_SPEC_PLACEHOLDER", partial_spec)
        .replace("SOURCE_CODE_PLACEHOLDER", source_code)
    )


def gen_sockopt_arg_prompt(
    file_path: Path, syzkaller_spec: str, source_code: str
):
    sockopt_arg_template = SOCKOPT_ARG_TEMPLATE_PATH.read_text()
    file_path_str = file_path_to_placeholder(file_path)
    return (
        sockopt_arg_template.replace("PATH_PLACEHOLDER", file_path_str)
        .replace("INPUT_SYZKALLER_PLACEHOLDER", syzkaller_spec)
        .replace("MISSING_SOURCE_CODE_PLACEHOLDER", source_code)
    )


def find_missing_ioctl(info_dict: dict, file_path: Path, only_func=False):
    if info_dict is None:
        return False, None

    missing_types = info_dict["type"] if not only_func else []
    missing_funcs = info_dict["function"]
    return find_missing_code(missing_types, missing_funcs, file_path)


def find_missing_code(missing_types, missing_funcs, file_path):
    missing_source_code = ""
    file_path = Path(file_path).absolute().resolve().as_posix()

    all_failed = True
    for missing in missing_types + missing_funcs:
        if "->" in missing:
            continue
        logger.info(f"[{file_path}] Finding missing {missing}")
        if missing in missing_funcs:
            find_fn = find_function
            another_fn = find_type
        else:
            find_fn = find_type
            another_fn = find_function
        miss_res = find_fn(missing, file_path)
        if not miss_res:
            # Try to find the missing in other files
            miss_res = another_fn(missing, file_path)
        if not miss_res and (
            missing.startswith("struct_") or missing.startswith("struct ")
        ):
            # Try to find the missing without the prefix
            miss_res = find_fn(missing[7:], file_path)
            if not miss_res:
                miss_res = another_fn(missing[7:], file_path)
        if not miss_res and (
            missing.startswith("union_") or missing.startswith("union ")
        ):
            # Try to find the missing without the prefix
            miss_res = find_fn(missing[6:], file_path)
            if not miss_res:
                miss_res = another_fn(missing[6:], file_path)
        if not miss_res:
            logger.error(f"[{file_path}] Failed to find missing {missing}")
            with open("missing.txt", "a") as f:
                f.write(f"{file_path},{missing}\n")
        else:
            all_failed = False
            logger.info(f"[{file_path}] Found missing {missing}")
            this_missing_source_code = miss_res["source"]
            missing_source_code += this_missing_source_code + "\n"
    if all_failed:
        return False, None
    return True, missing_source_code


def is_booting_dev_files(file_name: str):
    for dev_file in dev_files:
        # if dev_file.startswith(file_name.split("#")[0]):
        if dev_file.startswith(file_name.replace("#", "0")):
            return True
    return False


def is_existing_type(type_name: str):
    if type_name in existing_types:
        return True
    return False


def is_existing_cmd(cmd_name: str):
    if cmd_name in existing_cmds:
        return True
    return False


def is_existing_ioctl(ioctl_spec: str):
    """Whether the ioctl spec is existing."""
    # Extract the cmd
    pattern = r"const\[(\w+)\]"
    match = re.search(pattern, ioctl_spec)
    cmd = match.group(1) if match else None
    if cmd is None:
        logger.error(f"Failed to extract cmd from {ioctl_spec}")
        return False
    return is_existing_cmd(cmd)


def is_existing_filename(filename: str):
    if filename.startswith("anon"):
        return "anno"
    if (
        filename in existing_filenames
        or filename.replace("#", "") in existing_filenames
        or (filename + "#") in existing_filenames
    ):
        return True
    return False


class SyzSpec:
    fields = ["ioctls", "types", "existing_ioctls"]

    def __init__(self) -> None:
        self.data = {}
        # Init the fields
        for field in self.fields:
            if field not in self.data:
                self.data[field] = {}

    def get_open_filename(self):
        if "filename" not in self.data["open"]:
            return None
        return self.data["open"]["filename"]

    def get_open_fd(self):
        if "fd_name" not in self.data["open"]:
            return None
        return self.data["open"]["fd_name"]

    def is_existing_filename(self):
        filename = self.get_open_filename()
        if filename is None:
            return True
        return is_existing_filename(filename)

    def is_existing_fd(self):
        fd = self.get_open_fd()
        if fd is None:
            return True
        return fd in existing_fds

    def ioctl_skip(self):
        if (
            self.data is None
            or self.data.get("ioctls") is None
            or len(self.data["ioctls"]) == 0
        ):
            logger.error("No ioctls found")
            return True
        return False

    def distill_unknown_ioctls(self):
        """Distill the unknown ioctls."""
        if self.ioctl_skip():
            return
        unknown_cmd_ioctls = self.pop_unknown_cmd_ioctls()
        self.data["unknown_cmd_ioctls"] = unknown_cmd_ioctls

    def add_ioctls(self, ioctl_code, only_types=False):
        try:
            ioctls = json.loads(ioctl_code)
            new_types = ioctls["types"] if "types" in ioctls else {}
            new_ioctls = ioctls["ioctls"] if "ioctls" in ioctls else {}

            self.update_types("types", new_types)
            if not only_types:
                self.update_ioctls(new_ioctls)
        except Exception as e:
            logger.error(f"Failed to parse {ioctl_code}")
            logger.error(e)

    def update_ioctls(self, ioctls: dict):
        for new_ioctl in ioctls:
            if new_ioctl in self.data["ioctls"]:
                if self.data["ioctls"][new_ioctl] is None:
                    # Only update the None ioctl
                    self.data["ioctls"][new_ioctl] = ioctls[new_ioctl]
            else:
                self.data["ioctls"][new_ioctl] = ioctls[new_ioctl]

    def update_types(self, type_name, types: dict):
        for new_type in types:
            if new_type in self.data[type_name]:
                existing_type_data = types[new_type]
                if existing_type_data is None:
                    # Only update the None type
                    self.data[type_name][new_type] = types[new_type]
            else:
                self.data[type_name][new_type] = types[new_type]

    def pop_unknown_cmd_ioctls(self) -> list:
        if self.ioctl_skip():
            return {}
        if "unknown" not in self.data["ioctls"]:
            return []
        unknown_cmd_ioctls = self.data["ioctls"]["unknown"]
        self.data["ioctls"].pop("unknown")
        return unknown_cmd_ioctls

    def pop_unknown_arg_ioctls(self, skip_existing=True) -> dict:
        if self.ioctl_skip():
            return {}
        unknown_arg_ioctls = {}
        remaining_ioctls = {}
        existing_ioctls = {}
        for cmd_name, cmd_data in self.data["ioctls"].items():
            if cmd_name.lower() == "unknown":
                continue
            if skip_existing and is_existing_cmd(cmd_name):
                existing_ioctls[cmd_name] = cmd_data
            elif cmd_data["arg"] == "UNKNOWN_ARG":
                # Pop the ioctl from the dict
                if cmd_data["arg_inference"] is None:
                    cmd_data["arg"] = "intptr"
                    remaining_ioctls[cmd_name] = cmd_data
                else:
                    unknown_arg_ioctls[cmd_name] = cmd_data
            else:
                remaining_ioctls[cmd_name] = cmd_data

        self.data["ioctls"] = remaining_ioctls
        if "existing_ioctls" not in self.data:
            self.data["existing_ioctls"] = existing_ioctls
        else:
            self.data["existing_ioctls"].update(existing_ioctls)
        return unknown_arg_ioctls


def pop_unknown_types(type_dict, pop_all=False) -> dict:
    """
    Pop the unknown types from the type dict.
    This will modify the type_dict, and return the unknown types.
    """
    if pop_all:
        # Pop all the types from the dict
        unknown_types = type_dict.copy()
        for t in unknown_types:
            type_dict.pop(t)
        return unknown_types

    unknown_types = {}
    for t, type_def in type_dict.copy().items():
        if type_def is None or type_def == "UNKNOWN":
            # Pop the unknown from the dict
            unknown_types[t] = type_def
            type_dict.pop(t)
    return unknown_types


def update_types(type_dict: dict, answer_txt: str):
    try:
        new_types = json.loads(answer_txt)
    except Exception as e:
        logger.error(f"Failed to parse {answer_txt}")
        logger.error(e)
        return

    if "types" not in new_types:
        return
    for new_type in new_types["types"]:
        if new_type in type_dict:
            if type_dict[new_type] is None or type_dict[new_type] in [
                "UNKNOWN",
                "UNFOUND",
            ]:
                # Only update the None, UNKNOWN, UNFOUND type
                type_dict[new_type] = new_types["types"][new_type]
        else:
            type_dict[new_type] = new_types["types"][new_type]


def merge_init_ioctl(init_dict, ioctl_dict):
    if ioctl_dict is None:
        return init_dict
    if init_dict is None:
        logger.error("init_dict is None")
        return {}

    for top_k in ioctl_dict:
        if top_k not in init_dict:
            init_dict[top_k] = ioctl_dict[top_k]
        else:
            if not isinstance(init_dict[top_k], dict):
                continue
            for k in ioctl_dict[top_k]:
                if k not in init_dict[top_k]:
                    init_dict[top_k][k] = ioctl_dict[top_k][k]
    return init_dict


def update_spec_dict(spec_dict, answer_txt):
    try:
        new_spec_dict = json.loads(answer_txt)
    except Exception as e:
        logger.error(f"Failed to parse {answer_txt}")
        logger.error(e)
        return

    for k in new_spec_dict:
        if k not in spec_dict:
            spec_dict[k] = new_spec_dict[k]
        else:
            if not isinstance(spec_dict[k], dict):
                continue
            for sub_k in new_spec_dict[k]:
                if sub_k not in spec_dict[k] or spec_dict[k][sub_k] is None:
                    spec_dict[k][sub_k] = new_spec_dict[k][sub_k]


def skip_spec(spec_dict, key_name):
    if key_name not in spec_dict or len(spec_dict[key_name]) == 0:
        return True
    return False


def pop_unknown_spec(spec_dict, key_name):
    if key_name not in spec_dict:
        return []
    if "unknown" not in spec_dict[key_name]:
        return []
    unknown_spec = spec_dict[key_name]["unknown"]
    spec_dict[key_name].pop("unknown")
    return unknown_spec


def pop_unknown_args(spec_dict, key_name, arg_name):
    if key_name not in spec_dict:
        return {}
    unknown_args = {}
    existing_spec = {}
    for spec_name, spec_data in spec_dict[key_name].copy().items():
        # TODO: Support skip the existing args
        if arg_name not in spec_data:
            spec_dict[key_name].pop(spec_name)
            continue
        if spec_name in existing_sockopts:
            existing_spec[spec_name] = spec_data
            spec_dict[key_name].pop(spec_name)
            continue
        if arg_name in spec_data and "UNKNOWN_" in spec_data[arg_name]:
            unknown_args[spec_name] = spec_data
            spec_dict[key_name].pop(spec_name)

    if "existing_" + key_name not in spec_dict:
        spec_dict["existing_" + key_name] = existing_spec
    else:
        spec_dict["existing_" + key_name].update(existing_spec)
    return unknown_args
