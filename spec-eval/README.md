# Run Syzkaller with different specs

Prepare `config.yaml` and `kernel.config` files in a directory and run:

```
python run-specs.py -d DIRECTORY |& tee run-specs.log
# or
taskset --cpu-list 10-63 python run-specs.py -d DIRECTORY |& tee run-specs.log
```

The script will:

* Shallow clone a `linux` with the provided `kernek.config`
* Shallow clone a `syzkaller` for each run in `config.yaml`
* Copy specs into each `syzkaller` and build `syzkaller`
* Insert enabled calls into `template.cfg` for each run
* Run with `syzkaller.sh` script until timeout

The setup stage could take some time since it builds several syzkaller instances
and one linux kernel instance.

# Other scripts

`dst-spec-file-name` is the **file name** to be replaced, not a path. It should
exist under `syzkaller/sys/linux`.

* `add-new-spec.sh src-spec-path dst-spec-filename syzkaller-dir`: add `src-spec-path` to `syzkaller-dir` replacing the existing `dst-spec-filename`
* `check-spec-syntax.sh src-spec-path dst-spec-file-name`: a slow way to check syntax for `src-spec-path`.
* `shallow-clone.sh src-dir dst-dir`: shallow clones a git directory `src-dir` to `dst-dir` with the `HEAD` commit in `src-dir`.
