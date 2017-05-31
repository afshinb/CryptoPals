#!/usr/bin/python

import binascii

def modexp(g,a,p):
    '''(g**a)%p  calculate g**a mod p'''
    mask = 1
    d = dict()  # cache to keep result of g,g2,g4,g8,...
    d[1] = g % p
    while mask <= a:
        d[mask<<1] = (d[mask] ** 2) % p
        mask = mask << 1

    mask = 1
    result = 1
    while mask <= a:
        if mask & a:
            result = (result * d[mask]) % p
        mask = mask << 1
    return result


def invmod(x,N):
    '''ax = 1 mod N.
    find inverse of a number mod N. 
    Solves ax + bN = 1'''
    # Euclid Algorithm
    (t,newt) = (0,1)
    (r,newr) = (N,x)
    while newr !=0:
        q = r / newr
        (t,newt) = (newt, t - q*newt)
        (r,newr) = (newr, r - q*newr)
    if r > 1:
        raise Exception("x is not invertible")
    if t < 0:
        t += N
    return t




bin2int = lambda x: int(bin2hex(x),16)
hex2bin = lambda x: binascii.unhexlify(x)
bin2hex = lambda x: binascii.hexlify(x)

def int2bin(x):
    x = hex(x)
    x = x.replace('0x','')
    x = x.replace('L','')
    if len(x) % 2 != 0:
        x = '0' + x
    return binascii.unhexlify(x)


if __name__ == "__main__":
    print(modexp(2,5,23) , 32 % 23)
    print( modexp(5,230,37) , 28)
    print( modexp(7,98,131) , 20)

    invmod(2,5)
    invmod(17,3120)
