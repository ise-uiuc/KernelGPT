#!/usr/bin/bash
root=$(readlink -f $0 | xargs realpath | xargs dirname)

name=${1:-syz-manager}
corpus=${2:-corpus.db}
syz=${3:-"$root/syzkaller"}
linux=${4:-"$root/linux"}
image=${5:-"$root/image"}
config=${6:-"$root/template.cfg"}
port=${7:-$(python3 $root/get-port.py)}

fname="$name-$(date +%s)"
wkd="workdir-$fname"

mkdir -p $wkd
[[ -e $corpus ]] && cp $corpus $wkd/corpus.db
cat $config \
    | sed "s|__LINUX__|$linux|g" \
    | sed "s|__IMAGE__|$image|g" \
    | sed "s|__PORT__|$port|g" \
    | sed "s|__WKD__|$wkd|g" \
    | sed "s|__SYZKALLER__|$syz|g" \
    > $wkd/test.cfg

echo $port > $wkd/port.txt
echo $$ > $wkd/pid.txt

mkdir -p $wkd/cov
function get_cov() {
    local wkd=$1
    local port=$2
    local counter=0

    while true; do
        fname="$wkd/cov/rawcover-$(date +%s)"
        wget http://localhost:$port/rawcover -O $fname
        if [ $? -ne 0 ]; then
            ((counter++))
            rm -f $fname
        else
            counter=0
        fi
        if [ $counter -gt 8 ]; then
            break
        fi
        sleep 60
    done
}
get_cov $wkd $port &
PID=$!
echo $PID > $wkd/rawcover-pid.txt

"$syz/bin/syz-manager" -config=$wkd/test.cfg |& tee $wkd/$fname.log

