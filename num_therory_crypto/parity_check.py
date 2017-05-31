
import os
from crypto_math import *
from set5 import *
p = NIST_P
g = 2
p = 37
g = 5
def check_parity():
    a = bin2int(os.urandom(16))
    a = a % p
    pkA = pow(g,a ,p)
    parity = pow( 5, (p-1)/2, p)
    return a,parity
    print(a%2, parity)
    print(a)
    print('-'*33)

parity = 1
i = 0
while parity == 1:
    (a,parity) = check_parity()
    i += 1
    if i > 10:
        break
print(a,parity)

