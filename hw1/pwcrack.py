import argparse
import hashlib
from itertools import product
import string

parser = argparse.ArgumentParser()
parser.add_argument('--username', required=True)
parser.add_argument('--salt', required=True)
parser.add_argument('--digest', required=True)

args = parser.parse_args()

for i in range(1, 9):
    for password in product(string.digits, repeat=i):
        password = ''.join(password)
        s = f'{args.username},{password},{args.salt}'
        if hashlib.sha256(s.encode()).hexdigest() == args.digest:
            print(password)
            break