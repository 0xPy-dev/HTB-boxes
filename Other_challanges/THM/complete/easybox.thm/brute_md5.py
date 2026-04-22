import hashlib

salt = '1dac0d92e9fa6bb2'
hash_passwd = '0c01f4468bd75d7a84c7eb73846e8d96'
wordlist = open("/usr/share/wordlists/rockyou.txt", 'rb').read().split(b'\n')

def brute():
	print("Start brute")
	for word in wordlist:
		try:
			word = word.decode("utf-8")
			if hashlib.md5(str(salt+word).encode()).hexdigest() == hash_passwd:
				print("\nEND")
				print("PASSWORD: %s" % word)
				break
			
			else:
				print('\r'+word, end='')

		except:
			print(word)
			continue

if __name__ == '__main__':
	brute()