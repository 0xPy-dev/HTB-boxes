import requests
import binascii
import urllib
import base64
import string

charset = list(string.ascii_lowercase)+["aaaaaaaaaa", "aaaaaaaaab", "bbbbbbbbbb"]

url = "http://natas28.natas.labs.overthewire.org/index.php"
s = requests.Session()
s.auth = ('natas28', 'JWwR438wkgTsNKBbcJoowyysdM82YjeF')

sample = "aaaaaaaaa"

for x in charset:
    data = {'query':sample+x}
    r = s.post(url, data=data)
    cipher = r.url.split('=')[1]
    cipher = urllib.parse.unquote(cipher)
    print("[*] last char. = %s | %s" % (x, cipher))
