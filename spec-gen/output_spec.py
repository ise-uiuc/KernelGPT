import concurrent.futures
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from loguru import logger

linux_path = Path(__file__).parent.parent / "linux"
includes_path = Path(__file__).parent / "include-filter.txt"

resources_path = Path(__file__).parent / "existings" / "resources.txt"
default_includes = set(includes_path.read_text().splitlines())
PREFIX = "KGPT_"
TYPE_PREFIX = "kgpt_"
SUFFIX = "_kgpt"
SYSCALL_SPEC_KEY = "syscall_specs"
INIT_SYSCALL_KEY = "init_syscalls"

SKIP_EXSITING = False
existing_open_names = set()
existing_fd_names = set()
existing_cmds = set()
existing_types = set()
existing_syscalls = set()
existing_resources = set(resources_path.read_text().splitlines())

template = """meta arches["amd64"]

INCLUDE_PLACEHOLDER

RESOURCES_PLACEHOLDER

OPEN_PLACEHOLDER

SYSCALL_SPEC_PLACEHOLDER

TYPE_PLACEHOLDER
"""


syzkaller_primitive_types = [
    "int8",
    "int16",
    "int32",
    "int64",
    "intptr",
    "size",
    "ptrdiff",
    "ptr",
    "int",
    "uint",
    "long",
    "longlong",
    "ulonglong",
    "void",
    "string",
    "buffer",
    "filename",
    "fd",
    "dir",
    "sock",
    "float32",
    "float64",
    "float",
    "bool",
    "array",
]


def enable_skip_existing():
    global SKIP_EXSITING
    SKIP_EXSITING = True


def is_primitive_type(type_name: str):
    in_primitive_types = type_name in syzkaller_primitive_types
    if in_primitive_types:
        return True
    if type_name.startswith("flags["):
        return True
    if type_name.startswith("array["):
        return True
    if type_name.startswith("buffer["):
        return True
    if type_name.startswith("ptr["):
        return True
    return False


def get_open_str(spec_dict: dict):
    if INIT_SYSCALL_KEY not in spec_dict:
        logger.warning("Cannot find init syscall")
        logger.warning("Initializing syscall spec...")
        initialize_spec_dict(spec_dict)

    init_syscalls = spec_dict[INIT_SYSCALL_KEY]
    syscall_specs = spec_dict[SYSCALL_SPEC_KEY]

    output = ""

    for init_syscall_name in init_syscalls:
        spec = syscall_specs[init_syscall_name]

        splits = spec.split("(")
        open_name = splits[0]
        remaining = "(" + "".join(splits[1:])
        if SKIP_EXSITING:
            global existing_open_names
            while open_name in existing_open_names:
                open_name = open_name + "_dup"
            existing_open_names.add(open_name)
        output += open_name + remaining + "\n"
    return output


def get_include_str(includes: set):
    if not includes:
        return ""
    added_includes = set().union(default_includes)
    added_includes = sorted(list(added_includes))
    for i in includes:
        if i not in added_includes:
            added_includes.append(i)

    output = "\n".join([f"include <{i}>" for i in added_includes])
    return output


def get_resources_str(resources_dict: dict):
    output = []
    for fd_name, fd_dict in resources_dict.items():
        global existing_resources
        if fd_name in existing_resources:
            continue
        if SKIP_EXSITING:
            existing_resources.add(fd_name)
        output.append(fd_dict["spec"])
    output = "\n".join(output)
    return output


def get_ioctl_spec(cmd, arg_data, fd_name):
    arg_type = arg_data["arg"]
    if not isinstance(arg_type, str):
        logger.warning(f"Cannot find arg type for {cmd}")
        return ""
    cmd_name = cmd
    if SKIP_EXSITING:
        global existing_cmds
        while cmd_name in existing_cmds:
            cmd_name = cmd_name + "_dup"
        existing_cmds.add(cmd_name)
    remaining = ""
    if arg_type == "UNUSED_ARG":
        arg_spec = ", arg ptr[in, array[int8]]"
    else:
        lines = arg_type.splitlines()
        arg_type = lines[0]
        if len(lines) > 1:
            remaining = "\n" + "\n".join(lines[1:])
        arg_spec = f", arg {arg_type}"
    ioctl_spec = f"ioctl${PREFIX}{cmd_name}(fd {fd_name}, cmd const[{cmd}]{arg_spec}){remaining}"  # noqa E501
    return ioctl_spec


def get_ioctl_str(ioctl_dict: dict, fd_name):
    output_spec = ""
    for cmd, arg_data in ioctl_dict.items():
        ioctl_spec = get_ioctl_spec(cmd, arg_data, fd_name)
        output_spec += ioctl_spec + "\n"
    return output_spec


def get_sockopt_spec(cmd, arg_data, fd_name, is_getsockopt=True):
    arg_type = arg_data["val"]
    if not isinstance(arg_type, str):
        logger.warning(f"Cannot find arg type for {cmd}")
        return ""

    cmd_name = cmd
    if SKIP_EXSITING:
        global existing_cmds
        while cmd_name in existing_cmds:
            cmd_name = cmd_name + "_dup"
        existing_cmds.add(cmd_name)
    if arg_type == "UNUSED_ARG":
        direction = "out" if is_getsockopt else "in"
        arg_type = f"ptr[{direction}, array[int8]]"

    level = arg_data["level"]
    len_spec = arg_data["len"]
    syscall_name = "getsockopt" if is_getsockopt else "setsockopt"
    ioctl_spec = f"{syscall_name}${PREFIX}{cmd_name}(fd {fd_name}, level const[{level}], opt const[{cmd}], val {arg_type}, len {len_spec})"  # noqa E501
    return ioctl_spec


def get_type_str(types_dict: dict):
    str_list = []
    for type_name, type_def in types_dict.items():
        if type_name in ["PRIMITIVE", "UNFOUND", "EXISTING"]:
            continue
        if SKIP_EXSITING:
            global existing_types
            if type_name in existing_types:
                continue
            existing_types.add(type_name)
        if type_def.startswith("flags"):
            type_def = f"type {type_name} {type_def}"
        str_list.append(str(type_def))
    output = "\n".join(str_list)
    return output


def has_macro(content: str, macro: str):
    pattern1 = re.compile(
        r"(^|\n)(\s*)#define(\s+)" + re.escape(macro) + r"(\s+)"
    )
    pattern2 = re.compile(r"(^|\n)(\s*)" + re.escape(macro) + r"[(\s+),]")
    return pattern1.search(content) or pattern2.search(content)


def process_file(path, macro_set):
    if (
        "linux/arch/" in str(path) and "linux/arch/powerpc" not in str(path)
    ) or "linux/tools/" in str(path):
        return set(), set()

    includes = set()
    include_macros = set()
    try:
        with open(path, "r") as f:
            content = f.read()
            for macro in macro_set:
                if macro in content and has_macro(content, macro):
                    includes.add(path)
                    include_macros.add(macro)
    except Exception as e:
        print(f"Error processing file {path}: {e}")

    return (includes, include_macros)


def find_include_file(macro_set: set, max_workers=10):
    includes = set()
    header_files = list(linux_path.rglob("*.h"))
    # Exclude files in /usr/include
    header_files = [
        p for p in header_files if "linux/usr/include" not in str(p)
    ]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_file, path, macro_set): path
            for path in header_files
        }
        for future in concurrent.futures.as_completed(futures):
            res_includes, res_macros = future.result()
            includes.update(res_includes)
            macro_set.difference_update(res_macros)
            if not macro_set:
                break
    return includes


def path_to_syzkaller_include(path: Path):
    try:
        path = Path(path)
        path_str = str(path.relative_to(linux_path))
        if path_str.startswith("include/"):
            path_str = path_str[len("include/") :]
        return path_str
    except ValueError:
        return None


def extract_include(spec_dict: dict):
    pattern = r"[\[,\s+]([A-Z][0-9A-Z_]+)[\],(\s+)]"

    def collect_cmd(macro_set: set):
        if SYSCALL_SPEC_KEY not in spec_dict:
            raise ValueError("Cannot find syscall spec")
        syscall_specs = spec_dict[SYSCALL_SPEC_KEY]
        for syscall_spec in syscall_specs.values():
            matches = re.findall(pattern, syscall_spec)
            # Filter out the macro with PREFIX
            matches = [m for m in matches if not m.startswith(PREFIX)]
            macro_set.update(matches)

    macros_to_find = set()
    collect_cmd(macros_to_find)

    types = spec_dict["types"]
    for t, t_def in types.items():
        if t_def is None:
            continue

        if isinstance(t_def, dict):
            t_def_string = f"{t} = " + ", ".join(t_def.keys())
            t_def = t_def_string
            logger.warning(f"Type {t} is a dict, using {t_def_string}")

        pattern = r"\s+([A-Z][0-9A-Z_]+)[\],(\s+)]"
        # fine all macros in the type definition
        matches = re.findall(pattern, t_def)
        # add the first group of each match to the set
        macros_to_find.update(matches)

    if "open" in spec_dict:
        open_spec = spec_dict["open"]["spec"]
    elif "socket" in spec_dict:
        open_spec = spec_dict["socket"]["spec"]
    else:
        open_spec = ""
    matches = re.findall(pattern, open_spec)
    macros_to_find.update(matches)

    includes = set(spec_dict["includes"] if "includes" in spec_dict else [])
    # find the file that contains the macros
    new_include_paths = find_include_file(macros_to_find)
    if macros_to_find:
        log_path = "log-macro-no-header.txt"
        with open(log_path, "a") as f:
            f.write(f"{macros_to_find}\n")
        logger.warning(f"Cannot find macro in {macros_to_find}")
    includes.update(new_include_paths)
    include_header = set(
        [
            path_to_syzkaller_include(p)
            for p in includes
            if path_to_syzkaller_include(p)
        ]
    )
    return include_header, macros_to_find


def get_fd_name(spec_dict: dict):
    if "open" in spec_dict:
        open_dict = spec_dict["open"]
        fd_name = open_dict["fd_name"]
    elif "socket" in spec_dict:
        socket_dict = spec_dict["socket"]
        _, fd_name = parse_socket_spec(socket_dict["spec"])
    else:
        raise ValueError("Cannot find fd name")
    return fd_name


def get_syscall_str(spec_dict: dict, unique=False):
    if SYSCALL_SPEC_KEY not in spec_dict:
        logger.warning("Cannot find syscall spec")
        logger.warning("Initializing syscall spec...")
        initialize_spec_dict(spec_dict)
    if INIT_SYSCALL_KEY not in spec_dict:
        logger.warning("Cannot find init syscall")
        logger.warning("Initializing syscall spec...")
        initialize_spec_dict(spec_dict)

    syscall_specs = spec_dict[SYSCALL_SPEC_KEY]
    init_syscalls = spec_dict[INIT_SYSCALL_KEY]
    output_spec_str = ""
    for syscall_name, syscall_def in syscall_specs.items():
        if syscall_name in init_syscalls:
            continue

        if unique and syscall_name in existing_syscalls:
            for idx in range(200):
                new_name = f"{syscall_name}_{idx}"
                if new_name not in existing_syscalls:
                    existing_syscalls.add(new_name)
                    syscall_def = syscall_def.replace(syscall_name, new_name)
                    break
        else:
            existing_syscalls.add(syscall_name)
        output_spec_str += syscall_def + "\n"
    return output_spec_str


def parse_socket_spec(socket_init_spec: str):
    socket_ops_name = socket_init_spec.split("(")[0].split("$")[-1]
    socket_fd_name = socket_init_spec.split(" ")[-1]
    return socket_ops_name, socket_fd_name


def add_incurred_ops(spec_dict: dict, include_ops_path: Path):
    ioctl_ops_dict = {}
    ioctl_ops_fops_name = {}
    for ioctl_name, ioctl_data in spec_dict["ioctls"].items():
        if "fops" in ioctl_data:
            ioctl_ops_fops_name[ioctl_name] = ioctl_data["fops"]

    for ioctl_name, fops in ioctl_ops_fops_name.items():
        for filename in include_ops_path.glob("*.json"):
            if filename.name.startswith(fops + "#"):
                new_fops_dict = json.loads(filename.read_text())
                # Recursive search for fops
                add_incurred_ops(new_fops_dict, include_ops_path)
                ioctl_ops_dict[ioctl_name] = new_fops_dict
                break
        if ioctl_name not in ioctl_ops_dict:
            logger.warning(f"Cannot find fops for {ioctl_name}")
            print(fops)

    for ioctl_name, fops in ioctl_ops_dict.items():
        ioctL_key_name = f"ioctl${PREFIX}{ioctl_name}"
        if ioctL_key_name not in spec_dict[SYSCALL_SPEC_KEY]:
            continue
        current_spec = spec_dict[SYSCALL_SPEC_KEY][ioctL_key_name]
        if current_spec[-1] != ")":
            # It has a return fd
            logger.warning(f"Has return fd for {ioctL_key_name}")
            continue

        print(spec_dict["resources"])
        print(fops)
        print(fops["resources"])
        spec_dict["resources"].update(fops["resources"])
        new_fd_name = get_fd_name(fops)
        types = spec_dict["types"]
        for type_name, type_def in fops["types"].items():
            if type_name not in types:
                types[type_name] = type_def
        for syscall_name, syscall_def in fops["syscall_specs"].items():
            if syscall_name not in spec_dict[SYSCALL_SPEC_KEY]:
                spec_dict[SYSCALL_SPEC_KEY][syscall_name] = syscall_def
        spec_dict[SYSCALL_SPEC_KEY][ioctL_key_name] = (
            current_spec + f" {new_fd_name}"
        )
        for include in fops["includes"]:
            if include not in spec_dict["includes"]:
                spec_dict["includes"].append(include)


def output_spec(
    spec_dict: dict,
    replace_name=False,
    unique=False,
    include_ops=False,
    include_ops_path=None,
):
    if "resources" in spec_dict:
        resources = spec_dict["resources"]
    elif "resources" in spec_dict["socket"]:
        resources = spec_dict["socket"]["resources"]
    else:
        raise ValueError("Cannot find resources")

    types = spec_dict["types"]
    include = set(spec_dict["includes"])

    if include_ops and include_ops_path is not None:
        add_incurred_ops(spec_dict, include_ops_path)

    output = (
        template.replace("INCLUDE_PLACEHOLDER", get_include_str(include))
        .replace("RESOURCES_PLACEHOLDER", get_resources_str(resources))
        .replace("OPEN_PLACEHOLDER", get_open_str(spec_dict))
        .replace("SYSCALL_SPEC_PLACEHOLDER", get_syscall_str(spec_dict, unique))
        .replace("TYPE_PLACEHOLDER", get_type_str(types))
    )
    if replace_name:
        for type_name in types:
            if not is_primitive_type(types[type_name]):
                type_name_pattern = re.compile(
                    r"\b" + re.escape(type_name) + r"\b"
                )
                output = type_name_pattern.sub(
                    f"{TYPE_PREFIX}{type_name}", output
                )
    return output


def initialize_proto_ops(spec_dict: dict):
    if "proto_ops" not in spec_dict:
        return
    if "socket_addr" not in spec_dict:
        return
    if "socket" not in spec_dict:
        return
    proto_ops = spec_dict["proto_ops"]
    sockaddr_type = spec_dict["socket_addr"]
    socket_fd_name = get_fd_name(spec_dict)

    ops_name = spec_dict["ops_name"]

    syscall_specs = (
        {} if SYSCALL_SPEC_KEY not in spec_dict else spec_dict[SYSCALL_SPEC_KEY]
    )

    if "bind" in proto_ops:
        bind_syscall_name = f"bind${PREFIX}{ops_name}"
        bind_spec = f"{bind_syscall_name}(fd {socket_fd_name}, addr ptr[in, {sockaddr_type}], addrlen len[addr])"  # noqa E501
        syscall_specs[bind_syscall_name] = bind_spec
    if "connect" in proto_ops:
        connect_syscall_name = f"connect${PREFIX}{ops_name}"
        connect_spec = f"{connect_syscall_name}(fd {socket_fd_name}, addr ptr[in, {sockaddr_type}], addrlen len[addr])"  # noqa E501
        syscall_specs[connect_syscall_name] = connect_spec
    if "accept" in proto_ops:
        accept_syscall_name = f"accept4${PREFIX}{ops_name}"
        accept_spec = f"{accept_syscall_name}(fd {socket_fd_name}, peer ptr[out, {sockaddr_type}, opt], peerlen ptr[inout, len[peer, int32]], flags flags[accept_flags]) {socket_fd_name}"  # noqa E501
        syscall_specs[accept_syscall_name] = accept_spec
    if "sendmsg" in proto_ops:
        sendmsg_syscall_name = f"sendto${PREFIX}{ops_name}"
        sendmsg_spec = f"{sendmsg_syscall_name}(fd {socket_fd_name}, buf ptr[in, array[int8]], len len[buf], f flags[send_flags], addr ptr[in, {sockaddr_type}, opt], addrlen len[addr])"  # noqa E501
        syscall_specs[sendmsg_syscall_name] = sendmsg_spec
    if "recvmsg" in proto_ops:
        recvmsg_syscall_name = f"recvfrom${PREFIX}{ops_name}"
        recvmsg_spec = f"{recvmsg_syscall_name}(fd {socket_fd_name}, buf ptr[out, array[int8]], len len[buf], f flags[recv_flags], addr ptr[in, {sockaddr_type}, opt], addrlen len[addr])"  # noqa E501
        syscall_specs[recvmsg_syscall_name] = recvmsg_spec
    spec_dict[SYSCALL_SPEC_KEY] = syscall_specs


def initialize_ioctl(spec_dict: dict, use_ops_name=False):
    if "ioctls" not in spec_dict:
        return

    unknown_cmd_ioctls = {}
    for cmd in spec_dict["ioctls"].copy():
        if cmd.startswith("UNKNOWN"):
            unknown_cmd_ioctls[cmd] = spec_dict["ioctls"][cmd]
            del spec_dict["ioctls"][cmd]
        cmd_arg = spec_dict["ioctls"][cmd]["arg"]
        if cmd_arg.startswith("UNKNOWN"):
            spec_dict["ioctls"][cmd]["arg"] = "ptr[in, array[int8]]]"
        elif cmd_arg in ["int32", "int", "int16"]:
            spec_dict["ioctls"][cmd]["arg"] = "intptr"
        elif cmd_arg == "string":
            spec_dict["ioctls"][cmd]["arg"] = "ptr[in, string]"
        elif not isinstance(cmd_arg, str):
            spec_dict["ioctls"][cmd]["arg"] = "ptr[in, array[int8]]"
        elif cmd_arg.startswith("flags["):
            pattern = re.compile(r"flags\[([a-zA-Z_]+),\s*int[a-zA-Z0-9]+\]")
            flag_res = pattern.findall(cmd_arg)
            if flag_res:
                flag = flag_res[0]
                spec_dict["ioctls"][cmd]["arg"] = f"flags[{flag}]"
    spec_dict["unknown_cmd_ioctls"] = unknown_cmd_ioctls

    syscall_specs = (
        {} if SYSCALL_SPEC_KEY not in spec_dict else spec_dict[SYSCALL_SPEC_KEY]
    )
    ops_name = spec_dict["ops_name"]
    fd_name = get_fd_name(spec_dict)
    for cmd, arg_data in spec_dict["ioctls"].items():
        if use_ops_name:
            ioctl_syscall_name = f"ioctl${PREFIX}{ops_name}_{cmd}"
        else:
            ioctl_syscall_name = f"ioctl${PREFIX}{cmd}"
        ioctl_spec = get_ioctl_spec(cmd, arg_data, fd_name)
        syscall_specs[ioctl_syscall_name] = ioctl_spec
    spec_dict[SYSCALL_SPEC_KEY] = syscall_specs


def initialize_sockopt(spec_dict: dict, is_getsockopt=True):
    keyname = "getsockopt" if is_getsockopt else "setsockopt"
    if keyname not in spec_dict:
        return

    unknown_cmd_sockopts = {}
    for cmd in spec_dict[keyname].copy():
        if cmd.startswith("UNKNOWN"):
            unknown_cmd_sockopts[cmd] = spec_dict[keyname][cmd]
            del spec_dict[keyname][cmd]

        cmd_val = spec_dict[keyname][cmd]["val"]
        cmd_len = spec_dict[keyname][cmd]["len"]
        if cmd_val.startswith("UNKNOWN"):
            direction = "out" if is_getsockopt else "in"
            spec_dict[keyname][cmd]["val"] = f"ptr[{direction}, array[int8]]"
        if cmd_len.startswith("UNKNOWN"):
            if is_getsockopt:
                spec_dict[keyname][cmd]["len"] = "ptr[inout, len[val, int32]]"
            else:
                spec_dict[keyname][cmd]["len"] = "len[val]"
        elif cmd_len.startswith("sizeof("):
            spec_dict[keyname][cmd]["len"] = "bytesize[val]"

    syscall_specs = (
        {} if SYSCALL_SPEC_KEY not in spec_dict else spec_dict[SYSCALL_SPEC_KEY]
    )
    fd_name = get_fd_name(spec_dict)
    for cmd, arg_data in spec_dict[keyname].items():
        sockopt_syscall_name = f"{keyname}${PREFIX}{cmd}"
        sockopt_spec = get_sockopt_spec(
            cmd, arg_data, fd_name, is_getsockopt=is_getsockopt
        )
        syscall_specs[sockopt_syscall_name] = sockopt_spec
    spec_dict[SYSCALL_SPEC_KEY] = syscall_specs


def initialize_socket(spec_dict: dict):
    if "socket" not in spec_dict:
        return

    socket_spec_name = spec_dict["socket"]["spec"].split("(")[0]
    splits = socket_spec_name.split("$")
    if len(splits) != 2:
        socket_op_name = splits[0]
        socket_name = spec_dict["ops_name"]
    else:
        socket_op_name = splits[0]
        socket_name = splits[1]
    remaining_str = spec_dict["socket"]["spec"][len(socket_spec_name) :]
    if not socket_name.startswith(PREFIX):
        socket_name = PREFIX + socket_name

    socket_syscall_name = f"{socket_op_name}${socket_name}"
    socket_syscall_def = socket_syscall_name + remaining_str
    spec_dict["socket"]["spec"] = socket_syscall_def

    syscall_specs = (
        {} if SYSCALL_SPEC_KEY not in spec_dict else spec_dict[SYSCALL_SPEC_KEY]
    )
    syscall_specs[socket_syscall_name] = socket_syscall_def
    spec_dict[SYSCALL_SPEC_KEY] = syscall_specs

    init_syscalls = (
        [] if INIT_SYSCALL_KEY not in spec_dict else spec_dict[INIT_SYSCALL_KEY]
    )
    init_syscalls.append(socket_syscall_name)
    spec_dict[INIT_SYSCALL_KEY] = init_syscalls


def initialize_open(spec_dict: dict):
    if "open" not in spec_dict:
        return

    open_spec_name = spec_dict["open"]["spec"].split("(")[0]
    splits = open_spec_name.split("$")
    if len(splits) != 2:
        open_op_name = splits[0]
        open_name = spec_dict["ops_name"]
    else:
        open_op_name = splits[0]
        open_name = splits[1]
    remaining_str = spec_dict["open"]["spec"][len(open_spec_name) :]
    if not open_name.startswith(PREFIX):
        open_name = PREFIX + open_name

    # Fix possible resource spec issue
    fd_name = spec_dict["open"]["fd_name"]
    fd_type = spec_dict["resources"][fd_name]["type"]
    spec_dict["resources"][fd_name]["spec"] = f"resource {fd_name}[{fd_type}]"

    open_syscall_name = f"{open_op_name}${open_name}"
    open_syscall_def = open_syscall_name + remaining_str
    spec_dict["open"]["spec"] = open_syscall_def

    syscall_specs = (
        {} if SYSCALL_SPEC_KEY not in spec_dict else spec_dict[SYSCALL_SPEC_KEY]
    )
    syscall_specs[open_syscall_name] = open_syscall_def
    spec_dict[SYSCALL_SPEC_KEY] = syscall_specs

    init_syscalls = (
        [] if INIT_SYSCALL_KEY not in spec_dict else spec_dict[INIT_SYSCALL_KEY]
    )
    init_syscalls.append(open_syscall_name)
    spec_dict[INIT_SYSCALL_KEY] = init_syscalls


def initialize_spec_dict(spec_dict: dict, use_ops_name=False):
    """Initialize the spec, only once"""
    initialize_open(spec_dict)
    initialize_socket(spec_dict)

    initialize_proto_ops(spec_dict)
    initialize_ioctl(spec_dict, use_ops_name)
    initialize_sockopt(spec_dict, is_getsockopt=True)
    initialize_sockopt(spec_dict, is_getsockopt=False)
    includes, _ = extract_include(spec_dict)
    print(includes)
    spec_dict["includes"] = list(includes)


def test():
    answer_path = Path("")
    answer = json.loads(answer_path.read_text())
    answer["includes"], _ = extract_include(answer, "socket")
    output_path = answer_path.parent / "step4-spec.txt"
    output_path.write_text(output_spec(answer))


if __name__ == "__main__":
    test()
