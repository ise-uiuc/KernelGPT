import argparse
import filecmp
import secrets
import shutil
import subprocess
from pathlib import Path
from time import sleep

import psutil
import yaml
from loguru import logger
from tqdm import trange

CURR = Path(__file__).parent.resolve()
PROJ_ROOT = Path(__file__).parent.parent.resolve()

ALLYES_CONFIG = PROJ_ROOT / "kernel-configs" / "allyesconfig.config"
SYZBOT_CONFIG = PROJ_ROOT / "kernel-configs" / "syzbot.config"


def check_return(returncode: int, msg: str):
    if returncode != 0:
        logger.error(f"Failed: {msg}")
        exit(returncode)
    else:
        logger.info(f"Done: {msg}")


def shallow_clone(src: Path, dst: Path):
    logger.info(f"Cloning {src} into {dst}")
    if not src.exists():
        logger.error(f"{src} does not exist.")
        exit(1)

    if dst.exists():
        logger.info(f"{dst} exists, skipping...")
        return

    r = subprocess.run(
        [
            CURR / "shallow-clone.sh",
            src,
            dst,
        ]
    )
    check_return(r.returncode, f"clone {src} into {dst}")
    if src.name == "syzkaller":
        logger.info("Apply patch for syzkaller")
        r = subprocess.run(
            [
                CURR / "apply-patch.sh",
                dst,
                CURR / "syzkaller-enabling.patch",
            ]
        )
        check_return(r.returncode, f"apply patch for {dst}")


def prepare_linux(wkd: Path, name="linux", config_path=None):
    shallow_clone(PROJ_ROOT / "linux", wkd / name)

    if config_path is None:
        if name == "linux":
            config_path = SYZBOT_CONFIG
        elif name == "linux_for_const":
            config_path = ALLYES_CONFIG
        else:
            raise ValueError(f"Unknown name: {name} for prepare_linux")
    shutil.copy(config_path, wkd / f"{name}/.config")
    shutil.copy(config_path, wkd / f"{name}/unmodified.config")


def build_linux(linux: Path, jobs, auto_check):
    vmlinux = linux / "vmlinux"
    if auto_check and vmlinux.exists():
        logger.info("vmlinux present, skip building linux")
        return

    subprocess.run(["make", "olddefconfig"], cwd=linux)

    logger.info(f"Building linux kernel at {linux}")
    r = subprocess.run(["make", "-j", str(jobs)], cwd=linux)

    check_return(r.returncode, f"build linux kernel at {linux}")


def create_shared_linux_with_config(config_path: Path, jobs: int):
    shared_linux_dir = CURR / "shared_linux_builds"
    shared_linux_dir.mkdir(exist_ok=True)

    new_name = f"{config_path.stem}_{secrets.token_hex(8)}"
    new_linux = shared_linux_dir / new_name
    prepare_linux(shared_linux_dir, new_name, config_path)
    build_linux(new_linux, jobs, auto_check=True)

    return new_linux


def get_shared_linux_with_config(config_path: Path, jobs: int):
    shared_linux_dir = CURR / "shared_linux_builds"
    shared_linux_dir.mkdir(exist_ok=True)

    for existing_conf in shared_linux_dir.rglob("unmodified.config"):
        if filecmp.cmp(config_path, existing_conf):
            return existing_conf.parent
    return create_shared_linux_with_config(config_path, jobs)


def use_shared_linux_with_config(wkd: Path, config_path: Path, jobs: int):
    shared_linux = get_shared_linux_with_config(config_path, jobs)
    wkd_linux = wkd / "linux"
    if wkd_linux.is_dir():
        logger.warning(
            f"{wkd_linux} already exists, "
            f"skipped creating a symlink to {shared_linux}"
        )
        return
    wkd_linux.symlink_to(shared_linux)


def populate_rundir(wkd: Path, run):
    run_dir = wkd / f"{run['name']}-tmp"
    run["run_dir"] = run_dir
    run_syz = run_dir / "syzkaller"
    run["run_syz"] = run_syz


def prepare_run(wkd: Path, run, jobs):
    run_dir = run["run_dir"]

    logger.info(f"Preparing: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Preparing syzkaller for {run_dir}")
    run_syz = run["run_syz"]
    shallow_clone(PROJ_ROOT / "syzkaller", run_syz)

    spec_dir = run_syz / "sys/linux"
    logger.info(f"Copying specs to {spec_dir}")
    for spec in run["specs"]:
        if len(spec) == 1:
            shutil.copy(PROJ_ROOT / spec[0], spec_dir)
            logger.info(f"Copied spec: {spec[0]}")
        elif len(spec) == 2:
            shutil.copy(PROJ_ROOT / spec[0], spec_dir / spec[1])
            logger.info(f"Copied spec: {spec[0]} to {spec_dir / spec[1]}")
        else:
            logger.erro("Too many spec paths, should be [spec, overwrite]")
    logger.info(f"Copied all specs to {run_dir}")

    logger.info(f"Removing conflicting files from {spec_dir}")
    for fn in run["remove_files"]:
        path = spec_dir / fn
        if path.is_file():
            path.unlink()
        logger.info(f"Removed {path} from {spec_dir}")
    logger.info(f"Removed conflicting files from {spec_dir}")

    logger.info(f"Building syzkaller with new specs: {run_syz}")
    prepare_linux(wkd, name="linux_for_const")
    r = subprocess.run(
        [
            "tools/syz-env",
            "make",
            "extract",
            "TARGETOS=linux",
            f"SOURCEDIR={wkd / 'linux_for_const'}",
            "-j",
            str(jobs),
        ],
        cwd=run_syz,
    )
    check_return(r.returncode, f"extract constatns for {run_syz}")

    r = subprocess.run(["tools/syz-env", "make", "generate"], cwd=run_syz)
    check_return(r.returncode, f"generate Go files for {run_syz}")

    r = subprocess.run(["make", "-j", str(jobs)], cwd=run_syz)
    check_return(r.returncode, f"build syzkaller: {run_syz}")


def prepare_template_config(wkd: Path, run, custom_template):
    logger.info(f"Creating template config file for {wkd}")
    if custom_template.is_file():
        logger.info(f"Using custom template config file: {custom_template}")
        template = open(custom_template, "r")
    elif len(run["enabled_calls"]) == 0:
        logger.info("Using default template config file enabling all calls")
        template = open(CURR / "template-all.cfg", "r")
    else:
        logger.info("Using default template config file")
        template = open(CURR / "template.cfg", "r")
    copy = open(run["run_dir"] / "template.cfg", "w")
    for line in template:
        line = line.replace(
            "__ENABLED_CALLS__",
            ",".join([f'"{c}"' for c in run["enabled_calls"]]),
        )
        if "__KNOWN_BUGS__" in line:
            known_bugs = (
                (PROJ_ROOT / "spec-utils/known_bugs.txt")
                .read_text()
                .splitlines()
            )
            line = line.replace(
                "__KNOWN_BUGS__", ",".join([f'"{b}"' for b in known_bugs])
            )
        copy.write(line)
    copy.close()
    logger.info(f"Done create template config file for {wkd}")


def run_syzkaller(wkd, run):
    corpus = wkd / "corpus.db"
    if corpus.is_file():
        corpus_s = corpus.as_posix()
    else:
        corpus_s = '""'
    commands = [
        (PROJ_ROOT / "syzkaller.sh").as_posix(),
        run["name"],
        corpus_s,
        run["run_syz"].as_posix(),
        (wkd / "linux").as_posix(),
        '""',  # bullseye image
        (run["run_dir"] / "template.cfg").as_posix(),
        '""',  # auto port number
    ]
    logger.info(f"Syzkaller Command: {' '.join(commands)}")
    proc = subprocess.Popen(
        " ".join(commands),
        shell=True,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        cwd=wkd,
    )
    logger.info(f"Started syzkaller for {run['name']}, PID: {proc.pid}")
    return proc


def stop_syzkaller(pid):
    sh = psutil.Process(pid)
    for c in sh.children(recursive=True):
        if "syz" in c.name():
            logger.info(f"Terminating: {c.name} {c.pid}")
            c.kill()
    logger.info(f"Terminating the shell: {sh.pid}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--dir",
        type=str,
        required=True,
        help="path to the directory containing the configuration file",
    )
    parser.add_argument(
        "-c",
        "--cfg",
        type=str,
        default="config.yaml",
        help="the name of the configuration file, default = config.yaml",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        required=False,
        default=64,
        help="same as make -j (for compilation only)",
    )
    parser.add_argument(
        "--skip-run",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="skip running syzkaller, default = False",
    )

    parser.add_argument(
        "--skip-build-linux",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="skip building linux, default = False",
    )

    parser.add_argument(
        "--auto-build-linux",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="only build linux when vmlinux is not present, default = True",
    )

    parser.add_argument(
        "--use-shared-linux-with-config",
        type=str,
        default="",
        help="path to the kernel configuration file, will ignore",
    )

    parser.add_argument(
        "--skip-prepare-syzkaller",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="skip copy specs, extract constants, and compile syzkaller,"
        " default = False",
    )
    parser.add_argument(
        "--custom-template",
        type=str,
        default="",
        help="path to the custom template config file",
    )

    args = parser.parse_args()
    assert 1 <= args.jobs and args.jobs <= 128
    wkd = Path(args.dir).resolve()
    config_path = wkd / args.cfg

    with open(config_path, "r") as f:
        logger.info(f"Loaded configuration: {config_path}")
        config = yaml.safe_load(f)

    logger.add(wkd / f"{config['name']}.log", rotation="20MB", level="DEBUG")

    for run in config["runs"]:
        populate_rundir(wkd, run)

    if args.skip_prepare_syzkaller:
        logger.warning("Skip preparing Syzkaller...")
    else:
        for run in config["runs"]:
            prepare_run(wkd, run, args.jobs)

    if len(args.use_shared_linux_with_config) != 0:
        config_path = Path(args.use_shared_linux_with_config).resolve()
        if not config_path.is_file():
            raise ValueError(f"Cannot find {config_path}")
        use_shared_linux_with_config(wkd, config_path, args.jobs)
    else:
        prepare_linux(wkd)
        if args.skip_build_linux:
            logger.warning("Skip building Linux...")
        else:
            build_linux(wkd, args.jobs, args.auto_build_linux)

    if args.skip_run:
        logger.warning("Skip running Syzkaller...")
        exit(0)

    custom_template = CURR / args.custom_template
    for run in config["runs"]:
        prepare_template_config(wkd, run, custom_template)

    ps = []
    for run in config["runs"]:
        p = run_syzkaller(wkd, run)
        ps.append(p)
    logger.info("All runs started")
    logger.info(f"Fuzzing time is: {config['timeout']} mins")
    seconds = (config["timeout"] + 2) * 60
    interval = 1

    for _ in trange(seconds // interval):
        if not ps:
            logger.error("All syzkaller instances terminated early")
            exit(1)
        tmp = []
        for i in range(len(ps)):
            if ps[i].poll() is not None:
                logger.error("One syzkaller instance terminated early")
            else:
                tmp.append(ps[i])
        ps = tmp
        sleep(interval)

    for p in ps:
        stop_syzkaller(p.pid)
    logger.info("Fuzzing done, bye.")


if __name__ == "__main__":
    main()
