import subprocess as sbp

def brute(word):
    out = sbp.Popen(['./program', word], stdout=sbp.PIPE).stdout
    out = out.read()
    if out.count(b'Incorrect'):
        print("FALSE")
    else:
        print(out)
        print('WORD IS: %s' % word)
        exit(0)

def main():
    wordlist = open('random.dic', 'r').read().split('\n')
    for word in wordlist:
        brute(word)

if __name__ == '__main__':
    main()
