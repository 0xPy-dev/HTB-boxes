#!/bin/bash

ports=$(nmap -p- --min-rate=1000 -T4 $1 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
out_file=`echo "${1%.*}"`
echo "Scaning: $out_file"
nmap -Pn -sC -sV -p$ports -o $out_file
