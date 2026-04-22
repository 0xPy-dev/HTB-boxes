import base64
import requests as req

size = 16
user = 'natas28'
passwd = 'JWwR438wkgTsNKBbcJoowyysdM82YjeF'
url = 'http://natas28.natas.labs.overthewire.org/'

for i in range(8, size):
    res = req.post(url=url, auth=(user, passwd), data={'query': 'a'*i})
    print("Input size: %s\tURL size: %s" % (i, len(base64.b64decode(req.utils.unquote(res.url[60:])))))
    print("=" * 80)
    for block in range(5):
        print("Block %s data: %s" % (block+1, repr(base64.b64decode(req.utils.unquote(res.url[60:]))[block*size:(block+1)*size])))
        print()
