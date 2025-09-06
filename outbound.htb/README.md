# Outbound HTB Writeup]

## 1. Сканируем порты с помощью nmap

~~~
root@localhost:~# nmap outbound.htb -sC -sV -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-06 23:50 EEST
Nmap scan report for outbound.htb (10.10.11.77)
Host is up (0.097s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.88 seconds
~~~

Видим что нас перенаправляет на mail.outbound.htb
Добавим запись в /etc/hosts

