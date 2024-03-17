receiver=$1
directory=$(realpath ${2:-spec-eval})

TMP=".tmp_email.tmp"
NOTIFIED=".notified.tmp"

:>$NOTIFIED

while true; do
    :> $TMP
    find $directory -type d -name "crashes" | while read crashdir; do
        find $crashdir -name "description"| while read desc; do
            ds=$(cat $desc)
            if ! grep -q "$ds" $NOTIFIED; then
                echo "New crash found:" >> $TMP
                echo >> $TMP
                cat $desc >> $TMP
                echo >> $TMP
                echo $(realpath $desc) >> $TMP
                echo >> $TMP
                echo $ds >> $NOTIFIED
                search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$ds'))")
                echo "https://www.google.com/search?q=$search" >> $TMP
                echo >> $TMP
            fi
        done
    done
    if [ -s $TMP ]; then
        echo "Machine: $(hostname)" >> $TMP
        echo >> $TMP
        cat $TMP | mail -s "New Crash Found on $(hostname)" -a "From: syzkaller@$(hostname)" $receiver
    fi
    rm $TMP
    sleep 60
done

rm $NOTIFIED
