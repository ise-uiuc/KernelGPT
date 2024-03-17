#!/usr/bin/bash
if [ "$#" -ne 2 ]; then
    echo "shallow-clone.sh src-dir dst-dir"
    exit 1
fi

if [ -d $2 ]; then
    echo "$2 exists"
    exit 1
fi

commit=$(cd $1 && git rev-parse HEAD)
remote=$(cd $1 && git remote get-url origin)
echo "Cloning $remote commit $commit into $2"

mkdir -p $2
cd $2
git init
git remote add origin $remote
git fetch --depth 1 origin $commit
git checkout FETCH_HEAD

echo "Done"
