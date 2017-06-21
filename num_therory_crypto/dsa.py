""" simple implementation of DSA """

from crypto_math import *
from hashlib import sha1
import os

# hashing Algorithm
H = lambda x: bin2int(sha1(x).digest())
os_rand = lambda n: bin2int(os.urandom(n))

# A series of valid parameters

P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1


Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

class DSA():
    ''' Digital Signing Algorithm'''
    def __init__(self, newParam = False):
        self.p = P
        self.q = Q
        self.g = G
        self.N = 20     # 160 bit
        self.L = 128    # 1024 bit 
        self.x = None
        self.k = None
        if newParam:
            generate_parameters()

    def generate_parameters(self):
        pass
    
    def getPK(self):
        '''returns the public key'''
        return self.y
    
    def _getSK(self):
        '''returns the secret key'''
        return self.x

    def generate_key_pair(self):
        '''generate a public/private key pair'''
        # public key
        self.x = os_rand(self.N)
        while self.x > self.q:
            self.x = os_rand(self.N)

        # private key
        self.y = modexp(self.g,self.x,self.p)
        return
    
    def _set_key_pair(self,secret_key, nonce):
        self.x = secret_key
        self.k = nonce
        self.y = modexp(self.g,self.x,self.p)
    def set_key_pair(self,secret_key):
        self.x = secret_key
        self.y = modexp(self.g,self.x,self.p)

    def sign(self,msg):
        '''signs the msg'''
        # if we dont have a secret key generated
        if self.x == None:
            self.generate_key_pair()
        (p,g,q,N,x,k) = (self.p,self.g,self.q,self.N,self.x,self.k)
        # find a nonce smaller than q
        if self.k == None:
            k = os_rand(N)
            while k > q:
                k = os_rand(N)
        r = (modexp(g,k,p)) % q
        
        if r == 0:
            return None
        sr = (H(msg) + x*r) % q
        sl = invmod(k,q)
        assert sl * k % q == 1
        s = (sl * sr) % q
        if s == 0:
            return None

        return (r,s)

    def verify_signature(self,r,s,msg,y):
        '''verify the signature is correct
        r,s -> signature
        msg -> the signed msg
        y -> public key
        '''
        assert y == modexp(self.g,self.x,self.p)

        #### Test ^
        (p,q,g) = (self.p,self.q,self.g)
        assert r < q
        assert s < q
        w = invmod(s,q)
        assert w*s % q == 1
        u1 = (H(msg) * w ) % q
        u2 = (r * w) % q
        v = ((modexp(g,u1,p) * modexp(y,u2,p))%p) % q
        if v == r:
            return True
        return False


if __name__ == "__main__":
    d1 = DSA()
    msg1="Hello Test"
    msg2="Hello2"
    (R,S) = d1.sign(msg)
    assert d1.verify_signature(R,S,msg,d1.getPK())
    assert not d1.verify_signature(R,S,msg + "forged_msg",d1.getPK())
    print("Verified")
    print("Test finished")


