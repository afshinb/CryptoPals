#!/usr/bin/python

'''challenge set 6 from cryptopals.com
challenge 41-'''
import random
import os
from crypto_math import *
from hashlib import sha256
from hashlib import sha1
from Crypto.Cipher import AES
import hmac
import rsa
import dsa
import math
import re

################################
######## Chal 41
## Implement unpadded message recovery attack

def chal41():
    
    r1 = rsa.RSA()
    seen_cipher_texts = set()

    # Client sending message to server
    def send_enc_msg_to_server():
        '''sends an encypted message to server,
        returns the ras object and
        cipher text so we can feed it to server and attacker'''
        msg = '''{ time: 1356304276,social: '555-55-5555'}'''
        ct1 = r1.encrypt(msg)
        pt1 =r1.decrypt(ct1)
        assert pt1 == msg
        return ct1
    
    # Server decrypting msg
    def server_decrypt_msg(ct):
        '''the server decrypts the cipher text and adds it to a
        set and will not decrypt it in the future'''
        if ct in seen_cipher_texts:
            raise Exception("Cipher text seen before")
        pt = r1.decrypt(ct)
        seen_cipher_texts.add(ct)
        return pt

    def attacker_dec_msg(ct):
        ''' attacker sees the cipher text and asks the 
        server to decrypt the message by 
        Multiplying the cipher text by C and then dividing the 
        decrypted msg by C
        forged_ct = ct * S**e
        dec_msg = ct**d  * S**e**d
        dec_msg = msg * S ** 1'''
        S = 5
        try:
            server_decrypt_msg(ct)
            print("Server is buggy, decrypts the cipher text")
        except Exception as e:
            print("Server works correctly and doesn't decrypt duplicate msgs")
        # e is the publick key, N is the pq
        e,N = r1.getPK()
        forged_ct = (ct * S**e) % N
        forged_pt = server_decrypt_msg(forged_ct)
        # convert the msg to binary and take the invmod
        original_pt = int2bin((invmod(S,N) * bin2int(forged_pt)) % N)
        return original_pt

    
    # the client sends an encrypted msg to server
    ct = send_enc_msg_to_server()
    # server decrypts and responds for the first time
    original_pt = server_decrypt_msg(ct)
    # attacker has interceoted ct and now asks the 
    # server to decrypt it
    attacker_pt = attacker_dec_msg(ct)
    assert attacker_pt == original_pt
    print("challenge 41 works")


################################
######## Chal 42
## Bliechenbacher e=3 RSA attack

def find_prefix_cube_root(x,n):
    '''given a binary string x, find a y where
     y**3 = x || r, the number should start with x
     but can have n random trailing bytes
     This is used for chal42'''

    # add zeros to the end of binary 
    xlow = bin2int(x + n * "\x00")
    xhigh = bin2int(x + n * "\x11")
    # find an approximation for such number
    el = math.floor(100*(math.log(xlow,2)))/(3*100.)
    eh = math.ceil(100*(math.log(xhigh,2)))/(3*100.)
    yl = int(pow(2,el))
    yh = int(pow(2,eh))
    y0 = (yl + yh) / 2

    # use bisection to find a number that lies between
    # xlow and xhigh
    while not xlow < y0**3 < xhigh:
        if y0**3 < xlow:
            yl = y0
            y0 = y0 + (yh - y0)/2
        else:
            yh = y0
            y0 = y0 - (y0-yl)/2

    return y0
    

def chal42():
    keyL = 2048/8
    msg = "hi mom"
    
    r1 = rsa.RSA()

    def poor_signature_verifier(sig):
        ''' verifies that the signature is correct
        '''
        # create an RSA module and encrypt the msg
        # this is like saying m**3 which should give us the signature
        validation = int2bin(r1.encrypt(sig))
        if validation[0] == '\x01':
            j = 1
            while validation[j] != '\x00':
                j += 1
            if validation[j] != '\x00':
                print("error in the padding")
            
            if validation[j+1:j+33] == sha256(msg).digest():
                result = True
                print("valid signature")
            else:
                result = False
                print("invalid signature")

        return result
        

    def sign_msg():
        ''' creates a message and signs it using RSA'''
        h = sha256(msg).digest()
        # now pad the message 00 01 ff ff ... 00 ASN.1 HASH
        # Skipping ASN.1 for simplicity
        # the key is 2048 bits, sha256 is 256bits
        padded_msg = "\x00" + "\x01" + (keyL-256/8-3)*"\xff" + "\x00" + h
        assert len(padded_msg) == 2048/8
        # create 1024 bit RSA key and sign the message by decrypting it

        signature = r1.decrypt(bin2int(padded_msg))
        return signature
        

    def forge_sig():
        '''forge a signature knowing that I don't need a whole lot of \xff
        I just only need one or two'''
        (e,N) = r1.getPK()
        assert e == 3
        """ now we need to find a value x that when x**3 is calculated it yields
        0001ffff hash some garbage"""
        forged_msg = "\x01" + "\xff\xff\x00" + sha256(msg).digest()
        # we have 219 bytes we can as a prefix, we will use 60 of them as degrees of
        # freedom for finding a number and the 210 of the rest will be just zeros
        # which is equivalent to 40 suffix of 0
        return int2bin(find_prefix_cube_root(forged_msg,90) << 40)
    
    poor_signature_verifier(sign_msg())
    assert poor_signature_verifier(forge_sig()) == True
    print("challenge 42 done")

################################
######## Chal 43
## DSA key recovery from nonce

def DSA_secret_key_from_nonce(q,r,s,k,msg,H):
    '''returns the secret key given the nonce k
        x = (s*k - H(m)) * inv(r)  mod q '''
    invr = invmod(r,q)
    return ((s*k - H(msg)) * invr) % q

def chal43():
    # publik key : y

    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    msg = b"""For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""
    
    q = dsa.Q
    g = dsa.G
    p = dsa.P
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    # the hash function is SHA1
    H = lambda x: bin2int(sha1(x).digest())
    assert 0xd2d0714f014a9784047eaeccf956520045c45265 == H(msg)

    # we know that the k (nonce is 16 bit)
    def brute_force_DSA_SK():
        public_key = y
        for k in range(2**16):
            secret_key = DSA_secret_key_from_nonce(q,r,s,k,msg,H)
            if modexp(g,secret_key,p) == public_key:
                return secret_key,k
        print("couldnt find key :(")

    sk,nonce = brute_force_DSA_SK()

    d1 = dsa.DSA()
    d1._set_key_pair(sk,nonce)
    assert d1.getPK() == y
    (R,S) = d1.sign(msg)
    assert R == 548099063082341131477253921760299949438196259240
    assert S == 857042759984254168557880549501802188789837994940
    assert sha1(bin2hex(int2bin(sk))).hexdigest() == '0954edd5e0afe5542a4adf012611a91912a3ec16'
    print("Challenge 43 done!")



#############
if __name__ == "__main__":
    #chal41()
    #chal42()
    chal43()


