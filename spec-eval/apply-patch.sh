#!/usr/bin/bash
set -e
if [ "$#" -ne 2 ]; then
    echo "apply-patch.sh dst patch-file"
    exit 1
fi

if [ ! -d $1 ]; then
    echo "$1 not exists"
    exit 1
fi

cd $1
git apply $2

echo "Done"
