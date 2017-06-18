#!/usr/bin/python

'''challenge set 6 from cryptopals.com
challenge 41-'''
import random
import os
from crypto_math import *
from hashlib import sha256
from Crypto.Cipher import AES
import hmac
import rsa
import math


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

if __name__ == "__main__":
    chal41()



