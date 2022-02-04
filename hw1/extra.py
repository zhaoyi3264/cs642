import hashlib
import string

chr_cls = [
    set(string.ascii_uppercase),
    set(string.ascii_lowercase),
    set('~`!@#$%^&*()+=_-{}[]\|:;\"\'?/<>,.'),
    set(string.digits)
]

salt = '9578721033'.encode()
digest = '80cb3696e6fe9953e61048ad0013e4e9d31e26d0b10eec5650b26625033dfbe4203f1cc793e2df9031e96a1a877cce2f5da4cc8ec0698c382438aae4591a5d1a'

def count_chr_cls(password):
    s = set(password)
    return sum(map(lambda cls: len(s & cls) > 0, chr_cls))

def check(password):
    if len(password) < 6 or count_chr_cls(password) < 3:
        return False
    h = hashlib.scrypt(password=f'bucky,{password}'.encode(), salt=salt, n=16, r=32, p=1)
    return h.hex() == digest

f = open('crackstation.txt', 'r', encoding='ISO-8859-1')

for line in f:
    if check(line.strip()):
        print(line)
        with open('extra.txt', 'w') as ans:
            ans.write(line)
        break
f.close()