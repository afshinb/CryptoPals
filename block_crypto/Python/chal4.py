#!/usr/bin/python
from __future__ import print_function
from Crypto.Cipher import AES
from chal3 import *
from chal2 import *
from utils import *
import math
import hashlib
import socket
import random
from time import sleep
from time import time as tm
import re
from multiprocessing.pool import ThreadPool as Pool


# source code from:https://github.com/pcaro90/Python-SHA1/blob/master/SHA1.py
import sha1
# source code: https://gist.github.com/tristanwietsma/5937448
import md4
''' Cryptopals challenges set 4'''


####################
### Chal 25
# break random access read/write AES CTR


def _edit_enc(ct,key,nonce,start_pos, new_text):
    ''' lets the user modify the encrypted text, it takes the params:
    start_pos: index where the new text is going to be placed
    new_text: the new_text that would replace the old one '''

    aes = AES.new(key, AES.MODE_ECB , '0')

    # find the starting block and the last block
    block_start = int(start_pos/16)
    block_end = int(math.ceil((start_pos + len(new_text)) / 16))
    ct_blocks = create_blocks(ct,128/8)
    
    # decrypt the blocks from start to end
    # change the text and then encrypt them again
    pt_blocks = list()
    # decrypt the blocks
    print('block_end:%d' %block_end)
    for j in range(block_start,block_end):
        # get the jth block
        ct = ct_blocks[j]
        # encrypt the nonce || ctr
        _key = aes.encrypt(nonce+int2le(j))
        assert len(_key) == len(ct)
        pt = hexstr2bin(xor_string( bin2hexstr(_key), bin2hexstr(ct)))
        pt_blocks.append(pt)

    # modify the text
    pt_under_change = ''.join(pt_blocks)
    new_pt = pt_under_change[:start_pos%16] + new_text + pt_under_change[len(new_text) + start_pos%16:]
    assert len(new_pt)%16 == 0
    pt_blocks = create_blocks(new_pt,128/8)
    # encrypt again
    i = 0 
    for j in range(block_start,block_end):
        # set the jth block
        _key = aes.encrypt(nonce + int2le(j))
        assert len(_key) == len(pt_blocks[i])
        ct = hexstr2bin(xor_string(bin2hexstr(_key), bin2hexstr(pt_blocks[i])))
        ct_blocks[j] = ct
        i += 1

    return ''.join(ct_blocks)

def edit_enc(start_pos, new_text):
    '''api provided to the user.
    it can update part of an encrypted text and return the result
    to the user. They key and nonce and the plain text are kept secret
    and the user cannot access them'''
    with open('25.txt','r') as f:
        ct = f.read()
    # decrypt with key YELLOW SUBMARINE
    ct = ct.decode('base64')
    aes = AES.new('YELLOW SUBMARINE',AES.MODE_ECB, '0')
    pt = aes.decrypt(ct)
    
    key = 'YELLOW SUBMARINE'
    NONCE = '\x00'*8
    ct = AES_CTR_ENC(key,NONCE,pt)
    new_ct = _edit_enc(ct,key,NONCE,start_pos,new_text)
    return new_ct

def break_aes_rrw():
    '''decrypts the unknown plain text by making repeated
    calls to edit_enc function'''
    # step 1 : get the original text and store it -> M
    # step 2 : edit the ct and replace it with a known pt
    # and receive the new enc   -> P
    # C1 = K ^ M , C2 = K ^ P -> K = C2 ^ P, M = C1 ^ K
    c1 = edit_enc(0,'')
    print(len(c1))
    p = 'a' * len(c1)
    c2 = edit_enc(0,p)
    assert len(c2) == len(p)
    k_hex = xor_string(bin2hexstr(c2),bin2hexstr(p))
    m = hexstr2bin(xor_string(k_hex, bin2hexstr(c1)))
    print(m)
    return m

def chal25():
    '''set 4 chal25, recover plaintext using random acess rw
    api for editing aes ctr encrypted text
    moral result: don't encrypt a disk with fixed key in CTR mode!'''
    break_aes_rrw()

#######################
### chal26
# CTR bitflipping

def CTR_ENC(pt):
    '''escpae ; and = and encrypt under AES-CTR'''
    pt = pt.replace(';','";"')
    pt = pt.replace('=','"="')
    pt = "comment1=cooking%20MCs;userdata=" + pt + ";comment2=%20like%20a%20pound%20of%20bacon"
    key = 'YELLOW SUBMARINE'
    nonce = '\x00'*8
    ct = AES_CTR_ENC(key, nonce , pt)
    return ct

def CTR_ADM_PREV(ct):
    '''check if cookie has admin prev'''
    key = 'YELLOW SUBMARINE'
    nonce = '\x00'*8
    pt = AES_CTR_DEC(key,nonce,ct)
    # check if it is admin
    if ';admin=true;' in pt:
        print("Granting Admin previliges")
    else:
        print("User mode")
    return

def ctr_bitflip():
    '''produce a cookie with bitflipping to get admin prev'''
    target_string = 'xadminxtruexletmein'
    ct1 = CTR_ENC(target_string)
    flip = lambda x,y: hexstr2bin(xor_string(bin2hexstr(x),bin2hexstr(y)))

    a = chr( ord(ct1[32]) ^ ord('C'))
    b = chr( ord(ct1[32+6]) ^ ord('E'))
    c = chr( ord(ct1[32+11]) ^ ord('C'))
    ct = list(ct1)
    ct[32] = a
    ct[32+6] = b
    ct[32+11] = c
    ct = "".join(ct)
    CTR_ADM_PREV(ct)
    return

def chal26():
    ctr_bitflip()


##############
### chal 27
# recover key when IV is the same as key


def encrypt_with_same_IV_key(pt):
    
    if any((ord(c) > 128 for c in pt)):
        print('broken msg')

    key = 'YELLOW SUBMARINE'
    IV = key
    ct = AES_encrypt(key,IV , pt)
    
    return ct

def decrypt_with_same_IV_key(ct):
    key = 'YELLOW SUBMARINE'
    IV = key
    pt = AES_decrypt(key,ct)
    # drop the IV
    if any((ord(c) > 128 for c in pt)):
        raise Exception(pt)
    # do some stuff!
    # maybe DNS response
    return 

def same_IV_key_find_key():
    '''when encryption is done with key being equal to IV
    the key can be recovered'''
    crafted_msg = '8bytemsg' * 6
    enc_crafted = encrypt_with_same_IV_key(crafted_msg)
    enc_crafted = create_blocks(enc_crafted,128/8)
    # modify the second block and set it to 0
    # modify the 3rd block and set it equal to 1st one
    # now we can find the IV which is the key!
    #
    # well technically IV is just the first block
    # but I dont want to re-implement both
    # aes-encrypt+decrypt in CBC to remove it

    enc_crafted[2] = '\x00' * 16
    enc_crafted[3] = enc_crafted[1]
    # query the decrypt, it's gonna fail and give us
    # back the corrupt decrypted msg
    enc_crafted = ''.join(enc_crafted)
    try:
        decrypted_msg = decrypt_with_same_IV_key(enc_crafted)
    except Exception as e:
        decrypted_msg = e.args[0]

    decrypted_msg = create_blocks(decrypted_msg,128/8)
    print(decrypted_msg)
    key = hexstr2bin(xor_string(bin2hexstr(decrypted_msg[0]),bin2hexstr(decrypted_msg[2])))
    print("the key is:",key)


def chal27():
    same_IV_key_find_key()

###########################
#### chal28
# Implement SHA-1 Keyed MAC
import sha
def SHA1_(key,msg):
    ''' sha1( key || msg) '''
    return sha.new(key+msg).hexdigest()
    

def chal28():
    x1 = (SHA1_("YELLOW SUBMARINE","I'm calling you"))
    x2 = sha1.SHA1()
    x2.update("YELLOW SUBMARINE" + "I'm calling you")
    sha1_padding("YELLOW SUBMARINE" + "I'm calling you")
    assert x1 == x2.hexdigest()

##########################
#### chal29
# sha1 keyed mac length extension

def sha1_padding(strm):
    ''' add the proper sha1 padding for string
    assuming we get chunks in full bytes which
    seems reasonable'''
    big_endian64 = lambda x: hexstr2bin( hex_clean(hex(x)).rjust(16,'0') )
    strm += '\x80'
    l = len(strm)  #length in bytes
    
    m = l % 64
    if m == 0:
        m = 64
    strm += (m-8) * '\x00' + big_endian64(8*(l-1))
    #                           ^^^ length in bits
    print(repr(strm))
    return strm


def forge_sha1():
    ''' forge a sha1-mac that ends with ;admin=true added to the cookie'''
    cookie = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    x = sha1.SHA1()
    # secret
    x.update("we all live in a yellow sub")#marine ")
    x.update(cookie)
    mac = x.hexdigest() # --> attacker has this

    # now assuming you have the mac
    # forge it to authenticate the same msg
    # with ;admin=true; at the end

    rogue_sha = sha1.SHA1()
    bin2int = lambda x: int(x,16)
    reg = [bin2int(mac[i*8:(i+1)*8]) for i in range(5)]
    rogue_sha.__setState__(reg)
    rogue_sha.update(';admin=true;')
    print("the valid mac for the message is:",rogue_sha.hexdigest())
    
    # test to see if it works
    x.update(';admin=true;')
    #print(x.hexdigest())
    assert rogue_sha.hexdigest() == x.hexdigest()


def chal29():
    forge_sha1()

##################3
### chal 30
# break md4 by length extension
def forge_md4():
    ''' forge a md4-mac that ends with ;admin=true added to the cookie'''
    cookie = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    x = md4.MD4()
    # secret
    x.update("we all live in a yellow submarine ")
    x.update(cookie)
    mac = x.digest() # --> attacker has this
    # now assuming you have the mac
    # forge it to authenticate the same msg
    # with ;admin=true; at the end

    rogue_md4 = md4.MD4()
    rogue_md4.update("we all live in a yellow submarine "+cookie)
    bin2int = lambda x: int(x,16)
    reg = [bin2int(mac[i*8:(i+1)*8]) for i in range(4)]
    print(reg)
    rogue_md4.__setState__(reg)
    rogue_md4.update(';admin=true;')
    print("the valid mac for the message is:",rogue_md4.digest())
    
    # 
    x.update(';admin=true;')
    print(x.digest())
    


def chal30():
    pass
    '''could not find a md4 code yet!
    forge_md4()'''


####################
### chal 31
# timing attack on keyed HMAC

def HMAC_SHA1(key,msg,blocksize = 64):
    opad = 0x5c
    ipad = 0x36
    
    if ( len(key) > blocksize):
        raise ValueError("key is too long")

    if ( len(key) < blocksize):
        key = key + ( '\x00' * (blocksize-len(key)))

    assert len(key) == blocksize
    o_key_pad = ''.join([ chr(ord(x) ^ opad) for x in key ])
    i_key_pad = ''.join([ chr(ord(x) ^ ipad) for x in key ])
    hi = hashlib.sha1()
    ho = hashlib.sha1()
    hi.update(i_key_pad + msg)
    ho.update( o_key_pad + hi.digest() )
    return ho.digest()


# function run by the server on each request
def verify_mac(c, line):
    SECRET_KEY = "I'm your life I'm the one who takes you there"
    '''for the given file make sure the mac sent 
    by user is correct '''
    # it is insecure but it's ok!
    fileName = re.findall(r'file=(.*)&',line)[0]
    signature = re.findall(r'signature=(.*)',line)[0]
    #print(fileName,signature)
    signature = signature.decode('base64')
    _sig = HMAC_SHA1(SECRET_KEY, fileName)
    #print(repr(_sig))
    cmp = insecure_compare(_sig, signature, DELAY)
    if cmp:
        c.sendall("500")
    else:
        c.sendall("200")
    return

def insecure_compare(s1, s2, delay):
    n1 = len(s1)
    n2 = len(s2)
    if n1 != n2:
        print("wrong length",n1,n2)
        return False
    for i in range(n1):
        sleep(delay)
        if s1[i] != s2[i]:
            return False
    return True


def break_HMAC():
    template = "http://localhost:9000/test?file={!s}&signature={!s}"
    FileName = 'foo'
    # we know the length is 160 bits or 20 bytes
    fake_mac = 20 * ["\x00"]

    # timing attack, see if we can get a match on
    # the nth char of mac by timing how long it takes
    # to calculate the response
    s = socket.socket()
    s.connect(('localhost',9602))
    _ = s.recv(1024)
    j = 0
    best_time_dict = [0] * 20
    all_bytes = range(256)
    while j < 20:
        # dictionary to keep the response time for every char
        # we can use a list instead of dict
        timing_dict = [0] * 256
        for _ in range(10):
            random.shuffle(all_bytes)
            for c in all_bytes:
                fake_mac [j] = chr(c)
                req = template.format(FileName, ''.join(fake_mac).encode('base64'))
                # send a request to server and time it
                s.sendall(req)
                t0 = tm()
                resp_code = s.recv(1024)
                timing_dict[c] += (tm() - t0)
            s.close()
            s = socket.socket()
            s.connect(('localhost',9602))
            _ = s.recv(1024)
        # find the one that took the longest
        (index, char) = max(enumerate(timing_dict), key = lambda x: x[1])
        print(j,index,char)
        best_time_dict[j] = timing_dict[index]
        # check to see if there is improvement in timing
        if best_time_dict[j] > best_time_dict[j-1] + 0.75*DELAY:
            fake_mac[j] = chr(index)
            j += 1
        else:
            j -= 1
            print("Trying again for byte",j)
    print(fake_mac)
    req = template.format(FileName, ''.join(fake_mac).encode('base64'))
    s.sendall(req)
    resp_code = s.recv(1024)
    print("Response is:",resp_code)
    s.close()

def time_request(fake_mac,j,n):
    template = "http://localhost:9000/test?file={!s}&signature={!s}"
    FileName = 'foo'
    fake_mac[j] = chr(n)
    req = template.format(FileName, ''.join(fake_mac).encode('base64'))
    s = socket.socket()
    s.connect(('localhost',9602))
    _ = s.recv(1024)
    s.sendall(req)
    t0 = tm()
    resp_code = s.recv(1024)
    t = tm() - t0
    s.close()
    return n,t


def break_HMAC_multiThread():
    fake_mac = 20 * ["\x00"]
    best_time_dict = [0] * 20
    j = 0
    pool = Pool(4)
    while j < 20:
        timing_dict = [0] * 256
        byt = range(256)
        f = lambda n: time_request(fake_mac,j,n)
        for n,t in pool.map(f, byt):
            timing_dict[n] = t
        (index, char) = max(enumerate(timing_dict), key = lambda x: x[1])
        print(j,index,char)
        best_time_dict[j] = timing_dict[index]
        if best_time_dict[j] > best_time_dict[j-1] + 0.75*DELAY:
            fake_mac[j] = chr(index)
            j += 1
        else:
            j -= 1
            print("Trying again for byte",j)
    print(fake_mac)



DELAY = 0.005
def chal31():
    # timing attack on hmac
    # same for chal32, just change delay to lower value
    break_HMAC()


##################
######## MAIN
if __name__ == '__main__':
    #chal25()
    #chal26()
    #chal27()
    #chal28()
    #chal29()
    #chal30()
    chal31()

