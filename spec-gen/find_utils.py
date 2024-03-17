import json
import os
from pathlib import Path
from loguru import logger
from pprint import pprint

DATA_ROOT_PATH = Path(__file__).parent / "analyzer"
STRUCT_PATH = [
    DATA_ROOT_PATH / "processed_struct.json",
    DATA_ROOT_PATH / "processed_struct-typedef.json",
]
ENUM_PATH = [
    DATA_ROOT_PATH / "processed_enum.json",
    DATA_ROOT_PATH / "processed_enum-typedef.json",
]
FUNCTION_PATH = [
    DATA_ROOT_PATH / "processed_func.json",
]
USAGE_PATH = [
    DATA_ROOT_PATH / "processed_usage.json",
]

existing_structs = None
existing_functions = None
existing_enums = None
existing_usage = None


def find_name(name: str, path: str, data_dict: dict):
    path = str(Path(path).resolve().absolute().as_posix())
    if name not in data_dict:
        logger.warning(f"{name} not found in {path}")
        return None

    # Get definition from the most similar path name
    most_similar = max(data_dict[name], key=lambda x: path_similarity(path, x))
    return {"header": most_similar, "source": data_dict[name][most_similar]}


def load_data(path_list):
    data = {}
    for path in path_list:
        with open(path, "r") as f:
            data.update(json.load(f))
    return data


def find_type(name: str, path: str):
    global existing_structs
    if existing_structs is None:
        existing_structs = load_data(STRUCT_PATH)

    struct_info = find_name(name, path, existing_structs)
    if struct_info is not None:
        struct_info["type"] = "struct/union"
        return struct_info

    global existing_enums
    if existing_enums is None:
        existing_enums = load_data(ENUM_PATH)
    enum_info = find_name(name, path, existing_enums)
    if enum_info is not None:
        enum_info["type"] = "enum"
        return enum_info
    return None


def find_function(name: str, path: str):
    global existing_functions
    if existing_functions is None:
        existing_functions = {}
        for function_path in FUNCTION_PATH:
            with open(function_path, "r") as f:
                data = json.load(f)
            existing_functions.update(data)

    return find_name(name, path, existing_functions)


def find_usage(name: str, path: str):
    global existing_usage
    if existing_usage is None:
        existing_usage = {}
        for usage_path in USAGE_PATH:
            with open(usage_path, "r") as f:
                data = json.load(f)
            existing_usage.update(data)

    return find_name(name, path, existing_usage)


def path_similarity(path1, path2):
    """Calculate the similarity of two paths based on their components."""
    components1 = path1.split(os.sep)
    components2 = path2.split(os.sep)

    # Count the common components
    common_components = len(set(components1) & set(components2))
    total_components = len(set(components1) | set(components2))

    # Simple ratio of common components to total unique components
    return common_components / total_components


if __name__ == "__main__":
    definition = find_type(
        "tpg_data",
        "/home/chenyuan/projects/kernel-spec/linux/include/media/tpg/v4l2-tpg.c",  # noqa: E501
    )
    pprint(definition)

    definition = find_function(
        "nbd_set_size",
        "/home/chenyuan/projects/kernel-spec/linux/drivers/block/nbd.c",  # noqa: E501
    )
    pprint(definition)

    definition = find_usage(
        "_ctl_fops",
        "/home/chenyuan/projects/kernel-spec/linux/drivers/md/dm-ioctl.c:2162:1",  # noqa: E501
    )
    pprint(definition)
