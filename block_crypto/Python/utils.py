#!/usr/bin/python
import binascii
from Crypto.Cipher import AES
import os
import random

def bin2hexstr(x):
    return binascii.hexlify(x)
def hexstr2bin(x):
    return binascii.unhexlify(x)

def hex_clean(x):
    if x.endswith("L"):
        x = x[:-1]
    if x.startswith("0x"):
        x = x[2:]
    if len(x) % 2 != 0:
        x = '0'+ x
    return x

# two hex strings x,y returns hex string z
def xor_string(x,y,block_size=16):
    if x=='':
        x='00'
    if y=='':
        y='00'
    str2bin = lambda a: int(a,16)
    z = str2bin(x) ^ str2bin(y)
    z = hex_clean(hex(z))
    z = (2*block_size-len(z)) * '0' + z
    return z

# generate a key of size n bytes
def gen_key(n):
    return os.urandom(n)

# break text into blocks of given size
def create_blocks(txt, size):
    if len(txt)%size != 0:
        raise Exception("text is not properly padded. len(txt)=%d, size=%d" %(len(txt) ,size))
    L = list() 
    for i in range( len(txt)/size):
        L.append( txt[i*size:(i+1)*size] )
    return L


def AES_encrypt_CBC(key, IV, plain_text):
    # pad to complete 128bit
    plain_text = pkcs7_pad(plain_text, 128/8)
    # ECB mode doesnt use IV at all, just use 0
    aes = AES.new(key, AES.MODE_ECB, '0')
    bin2hexStr = lambda x: binascii.hexlify(x)
    hexStr2bin = lambda x: binascii.unhexlify(x)
    pt_blocks = create_blocks( plain_text, 128/8)
    ct_blocks = list()
    ct_blocks.append(IV)
    for pt in pt_blocks:
        ct_blocks.append((aes.encrypt(hexStr2bin(xor_string( bin2hexStr(pt), bin2hexStr(ct_blocks[-1]))))))

    # drop the IV? no
    return ''.join(ct_blocks)


# AES decrypt with CBC mode
def AES_decrypt_CBC(key, cipher_text):
    aes = AES.new(key, AES.MODE_ECB, '0')
    ct_blocks = create_blocks(cipher_text, 128/8)
    
    bin2hexStr = lambda x: binascii.hexlify(x)
    hexStr2bin = lambda x: binascii.unhexlify(x)
    pt_hex = list()
    for i,ct in enumerate(ct_blocks):
        if i==0: continue
        pt_hex.append(xor_string(bin2hexStr(aes.decrypt(ct)) , bin2hexStr(ct_blocks[i-1])))
    
    plain_text = map(hexStr2bin, pt_hex)
    return ''.join(plain_text)


def AES_encrypt_ECB(key, plain_text):
    aes = AES.new(key, AES.MODE_ECB,'0')
    return aes.encrypt(plain_text)

def AES_decrypt_ECB(key, cipher_text):
    aes = AES.new(key, AES.MODE_ECB, '0')
    return aes.decrypt(cipher_text)


# @param: pad_size is the block size in bytes
def pkcs7_pad(txt, block_size):
    if block_size >= 256:
        raise Exception("pad size is more than 256")
    p = block_size - (len(txt) % block_size)
    pad_char = binascii.unhexlify(hex_clean(hex(p)))
    txt = txt + (p*pad_char)
    if len(txt)%block_size != 0:
        raise Exception("pkcs7 padding error")
    return txt


if __name__ == "__main__":
    k1 = gen_key(128/8)
    iv = gen_key(128/8)
    ct = AES_encrypt_CBC(k1,iv, "YELLOW SUBMARINE")
    pt = AES_decrypt_CBC(k1, ct)
    print(pt)
