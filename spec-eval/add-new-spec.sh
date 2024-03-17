#!/usr/bin/bash
default_linux=$(realpath "$(dirname $0)/../linux")

linux=${4:-$default_linux}

if [ "$#" -ne 3 ]; then
    echo "add-new-spec.sh src-spec-path dst-spec-filename syzkaller-dir"
    exit
fi

echo "Coping $1 to $3/sys/linux/$2"
cp -f $1 $3/sys/linux/$2
cd $3

echo "Extracting constants..."
taskset -a --cpu-list 20-63 tools/syz-env make extract TARGETOS=linux SOURCEDIR=$linux
if [ $? -ne 0 ]; then
    echo "Failed to extract constants..."
    exit 1
fi

echo "Generating syzkaller files..."
taskset -a --cpu-list 20-63 tools/syz-env make generate
if [ $? -ne 0 ]; then
    echo "Failed to generate syzkaller files..."
    exit 1
fi

# Not using syz-env so that we can use taskset to limit CPU usage
echo "Building syzkaller..."
taskset -a --cpu-list 20-63 make -j40

echo "Done"
