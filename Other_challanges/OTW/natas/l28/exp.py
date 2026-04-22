import requests
import binascii
import urllib
import base64

url = "http://natas28.natas.labs.overthewire.org/index.php"
s = requests.Session()
s.auth = ('natas28', 'JWwR438wkgTsNKBbcJoowyysdM82YjeF')

sample = "aaaaaaaa"

while len(sample) < 16:
    data = {'query':sample}
    r = s.post(url, data=data)
    cipher = r.url.split('=')[1]
    cipher = urllib.parse.unquote(cipher)
    print("[*] %d chars.\t| %s" % (len(sample), cipher))
    sample += 'a'
