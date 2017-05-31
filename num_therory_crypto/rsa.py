from Crypto.Util import number
from crypto_math import *

def rand_prime(n=2048):
    '''returns a random prime of length n'''
    p = number.getPrime(n)
    # do ferma's test to make sure it's prime!
    assert modexp(2, p-1 , p) == 1
    return p


class RSA():
    '''RSA documents here'''
    def __init__(self):
        success = False
        while not success:
            try:
                self._keygen()
                success = True
            except Exception as e:
                success = False

    def _keygen(self):
        self.p = rand_prime()
        self.q = rand_prime()
        self.n = self.p * self.q
        self.et = (self.p-1) * (self.q-1)
        self.e = 3
        self.d = invmod(self.e,self.et)

    def getPK(self):
        '''return the publick key'''
        return (self.e, self.n)

    def getSK(self):
        '''return the secret key'''
        return (self.d, self.n)

    def _encrypt(self,m):
        '''encrypt the msg m'''
        return modexp(m, self.e, self.n)

    def _decrypt(self,c):
        '''decrypt the cipher text c'''
        return modexp(c, self.d, self.n)

    def encrypt(self,m):
        '''encrypt a string'''
        m = bin2int(m)
        print("rsa_enc:",m)
        return self._encrypt(m)

    def decrypt(self,c):
        '''decrypt a number and return a string'''
        m = self._decrypt(c)
        m = int2bin(m)
        return m



if __name__ == "__main__":
    r1 = RSA()
    c = r1.encrypt('1RSA!@RSAR')
    m = r1.decrypt(c)
    print(m)
