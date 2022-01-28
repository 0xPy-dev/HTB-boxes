#!/bin/bash

echo "INFO MACHINE: $(w | head -1 | awk '{print $2, $3}' | sed 's/\,//')";
echo "INFO USERS:   $(w | head -1 | awk '{print $4, $5}' | sed 's/\,//')";
echo "USER FLAG:    $(cat /home/matt/user.txt)";
echo "ROOT FLAG:    $(cat /root/root.txt)"
