#!/bin/bash

for i in {0000..9999};
do
    if ./leviathan6 $i | grep "Wrong";
    then
        printf "$i ";
    else
        echo $i;
        break
    fi
done
