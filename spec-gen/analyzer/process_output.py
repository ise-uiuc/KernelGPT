import json
from pathlib import Path
import re
import os
from loguru import logger
from argparse import ArgumentParser

linux_path = None
SKIP_SUBSYSTEMS = [
    "linux/net/",
    "linux/fs/",
    "linux/virt/",
]


def debug_output(data_dict, output_path: Path):
    # Recursively replace the value: \n -> \\n, \t -> \\t
    def replace_value(data):
        if isinstance(data, dict):
            for key, value in data.items():
                data[key] = replace_value(value)
        elif isinstance(data, list):
            for i in range(len(data)):
                data[i] = replace_value(data[i])
        elif isinstance(data, str):
            data = data.replace("\n", "\\n")
            data = data.replace("\t", "\\t")
        return data

    data_dict = replace_value(data_dict)
    output_path.write_text(json.dumps(data_dict, indent=2))


def extract_ioctl_function_name(code: str) -> str:
    """Extract the ioctl function name from the code."""
    pattern = r"\.(unlocked_)?ioctl\s*=\s*(\w+)[,\n]"
    match = re.search(pattern, code)
    if match:
        return match.group(2)
    return ""


def path_similarity(path1, path2):
    """Calculate the similarity of two paths based on their components."""
    components1 = path1.split(os.sep)
    components2 = path2.split(os.sep)

    # Count the common components
    common_components = len(set(components1) & set(components2))
    total_components = len(set(components1) | set(components2))

    # Simple ratio of common components to total unique components
    return common_components / total_components


def process_ioctl_handler():
    def output_data(data_dict, name_suffix=""):
        ioctl_names = list(data_dict.keys())
        ioctl_names.sort()
        handler_names = []
        for _, handler_data in data_dict.items():
            handler_names.extend(list(handler_data.keys()))
        handler_names = list(set(handler_names))
        handler_names.sort()
        Path(f"ioctl_names{name_suffix}.txt").write_text("\n".join(ioctl_names))
        Path(f"handler_names{name_suffix}.txt").write_text(
            "\n".join(handler_names)
        )

    jsonl_path = linux_path / "ioctl.jsonl"

    # The following dict {ioctl_name: {handler_name: {filename: source}}}}
    ioctl_data = {}
    ops_data = {}
    for line in jsonl_path.read_text().splitlines():
        data = json.loads(line)
        filename = data["filename"]
        source = data["source"]
        handler_name = data["name"]

        if handler_name not in ops_data:
            ops_data[handler_name] = {}
        ops_data[handler_name][filename] = source

        ioctl_name = extract_ioctl_function_name(source)
        if not ioctl_name:
            logger.warning(f"Cannot find ioctl function name in {filename}")
            continue

        if ioctl_name not in ioctl_data:
            ioctl_data[ioctl_name] = {}

        filepath = linux_path / filename.split(":")[0]
        abs_filename = filepath.absolute().resolve().as_posix()
        if handler_name not in ioctl_data[ioctl_name]:
            ioctl_data[ioctl_name][handler_name] = {}

        ioctl_data[ioctl_name][handler_name][abs_filename] = source

    ops_data_path = Path("processed_handlers.json")
    ops_data_path.write_text(json.dumps(ops_data, indent=2))
    debug_output(ops_data, ops_data_path.with_suffix(".debug.json"))

    # Write the data to a json file
    json_path = Path("processed_ioctl.json")
    json_path.write_text(json.dumps(ioctl_data, indent=2))

    # Print the analysis result
    print(f"Total number of ioctl: {len(ioctl_data)}")

    filtered_ioctl_data = {}
    for ioctl_name, handler_data in ioctl_data.items():
        cur_ioctl_data = {}
        for handler_name, filename_data in handler_data.items():
            handler_data = {}
            for filename, source in filename_data.items():
                skip = False
                for subsystem in SKIP_SUBSYSTEMS:
                    if subsystem in filename:
                        skip = True
                if skip:
                    continue
                handler_data[filename] = source
            if handler_data:
                cur_ioctl_data[handler_name] = handler_data
        if cur_ioctl_data:
            filtered_ioctl_data[ioctl_name] = cur_ioctl_data

    # Write the filtered data to a json file
    json_path = Path("processed_ioctl_filtered.json")
    json_path.write_text(json.dumps(filtered_ioctl_data, indent=2))

    print(f"Total number of ioctl after filtering: {len(filtered_ioctl_data)}")

    # Output the ioctl names and handler names
    output_data(ioctl_data)
    output_data(filtered_ioctl_data, "_filtered")


def process_type(file_name: str):
    file_path = linux_path / file_name

    # The following dict {type_name: {filename: source}}}
    type_data = {}
    for line in file_path.read_text().splitlines():
        line = line.strip()
        data = json.loads(line)
        type_name = data["name"]
        source_file_name = data["filename"]
        source_file_path = linux_path / source_file_name
        source_file_name = source_file_path.absolute().resolve().as_posix()
        source = data["source"]
        if type_name not in type_data:
            type_data[type_name] = {}
        type_data[type_name][source_file_name] = source

    # Write the data to a json file
    json_path = Path(f"processed_{file_path.stem}.json")
    json_path.write_text(json.dumps(type_data, indent=2))

    return type_data


def process_typedef(file_name: str, type_data: dict):
    file_path = linux_path / file_name

    # The following dict {type_name: {filename: source}}}
    typedef_data = {}
    for line in file_path.read_text().splitlines():
        line = line.strip()
        data = json.loads(line)
        type_name = data["name"]
        alias_name = data["alias"]
        source_file_name = data["filename"]
        source_file_path = linux_path / source_file_name
        source_file_name = source_file_path.absolute().resolve().as_posix()
        source = data["source"]
        if type_name not in typedef_data:
            typedef_data[type_name] = {}

        if alias_name and alias_name in type_data:
            alias_data = type_data[alias_name]
            most_similar = max(
                alias_data, key=lambda x: path_similarity(source_file_name, x)
            )
            source_most_similar = alias_data[most_similar]
            source = source + "\n" + source_most_similar

        typedef_data[type_name][source_file_name] = source

    # Write the data to a json file
    json_path = Path(f"processed_{file_path.stem}.json")
    json_path.write_text(json.dumps(typedef_data, indent=2))


def process_usage():
    file_path = linux_path / "usage.jsonl"

    # The following dict {fops_name: {filename: [source]}}}
    usage_data = {}
    for line in file_path.read_text().splitlines():
        line = line.strip()
        data = json.loads(line)
        fops_name = data["alias"]
        source_file_name = data["filename"]
        source_file_path = linux_path / source_file_name
        source_file_name = source_file_path.absolute().resolve().as_posix()
        source = data["source"]
        if fops_name not in usage_data:
            usage_data[fops_name] = {}
        usage_data[fops_name][source_file_name] = source

    # Write the data to a json file
    json_path = Path("processed_usage.json")
    json_path.write_text(json.dumps(usage_data, indent=2))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--linux-path", type=str, required=True)
    parser.add_argument("--usage", action="store_true")
    args = parser.parse_args()

    linux_path = Path(args.linux_path)

    if args.usage:
        process_usage()
    else:
        process_ioctl_handler()
        type_data = process_type("struct.jsonl")
        process_typedef("struct-typedef.jsonl", type_data)
        type_data = process_type("enum.jsonl")
        process_typedef("enum-typedef.jsonl", type_data)
        type_data = process_type("func.jsonl")
