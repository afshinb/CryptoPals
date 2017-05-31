#!/usr/bin/python
from __future__ import print_function
from time import sleep
from utils import *
import binascii
from Crypto.Cipher import AES
import os
import random
import string
from chal1 import *
import time


######
#####


# generate a single 128bit key
GLOBAL_KEY = gen_key(128/8)

###############
### chal 3.17
# CBC padding oracle
STRING_CHOICES=["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="\
,"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="\
,"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="\
,"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="\
,"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"\
,"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="\
,"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="\
,"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="\
,"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="\
,"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

# pick one of the strings and encrypt it with CBC
def cbc_enc_one_string():
   pt = random.choice(STRING_CHOICES).decode('base64')
   ct = AES_encrypt_CBC(GLOBAL_KEY, gen_key(128/8) , pt)
   return ct

# gets a cipher text and decrypts it (CBC)
# checks for valid padding
def padding_oracle(ct):
    pt = AES_decrypt_CBC(GLOBAL_KEY,ct)
    # check if padding is ok
    assert len(pt)% 16 ==0
    txt = remove_pkcs7_pad(pt, 128/8)
    return txt

# removes the CBC pads and
# raises exception if padding is not correct
def remove_pkcs7_pad(plain_text,block_size):
    txt_blocks = create_blocks(plain_text,block_size)
    
    # take a binary number and convert it to int
    bin2int = lambda x: int(binascii.hexlify(x),16)
    # we only care about last block
    last_block = txt_blocks[-1]
    # find the padding character
    pad_char = last_block[-1]
    num_pad_chars = bin2int(pad_char)
    pad_block =  last_block[-1*num_pad_chars:]
    # make sure all the pad characters are correct
    for c in pad_block:
        if c != pad_char:
            raise Exception("Invalid pkcs7 padding")
    return plain_text[:-1*num_pad_chars]


# given a cipher text, crack it using the padding oracle
# we have
# We will crack 1 byte at a time
# flip the cipher text to alter the bytes of next block
# we can check if the padding is valid to guess the value of that byte
def crack_padding_oracle(ct):
    # break cipher text into blocks
    cracked_pt = ''
    ct_blocks = create_blocks(ct, 128/8)
    N = len(ct_blocks)
    #crack_block(ct_blocks[:])
    for j in range(N-1):
        pt = crack_block( ct_blocks[:N-j])
        cracked_pt = pt + cracked_pt 
        #print('\r%s' %cracked_pt, end='')
    print()
    print(repr(cracked_pt), end = '\n')
    return


def crack_block(ct_blocks):
    cracked_sofar = ''
    for i in range(16):
        possible_chars = crack_nth_byte(ct_blocks,cracked_sofar)
        if len(possible_chars) > 2:
            raise Exception("Unknown case")
        elif len(possible_chars) == 1:
            c = possible_chars[0]
        else:
            assert '\x01' in possible_chars
            c = [c for c in possible_chars if c != '\x01'] [0]
        cracked_sofar = c + cracked_sofar
    return cracked_sofar



# crack the cipher text one at a time
# n is the number of byte we want to crack
def crack_nth_byte(ct_blocks, cracked_sofar):

    all_chars = map(lambda x: hexstr2bin(hex_clean(hex(x))), range(256))
    crafted_ct_blocks = ct_blocks[:]
    # how many chars are already decrypted
    n = len(cracked_sofar)
    if n > 15:
        raise Exception("Already cracked all the bytes here")
    if len(ct_blocks) < 2:
        raise Exception("Already done cracking everything")
    crack_block = ct_blocks[-1]
    prev_block = ct_blocks[-2]
    assert len(crack_block) == len(prev_block) == 16
    # change the prev block to make the known parts of 
    # the cipher to decrypt to zero
    prev_block = hexstr2bin(xor_string( bin2hexstr(prev_block),bin2hexstr(cracked_sofar)))
    # find a character that gives us a valid padding
    C = list()
    for c in all_chars:
        mal_block = hexstr2bin(xor_string( bin2hexstr(c + n*'\x00'), bin2hexstr(prev_block)))
        # we're cracking byte n+1
        # valid padding would be all n+1
        padding = hex_clean(hex(n+1)) * (n+1)
        crafted_ct_blocks[-2] = hexstr2bin(xor_string(padding, bin2hexstr(mal_block)))
        # if MSB is missing
        if len(crafted_ct_blocks[-2]) == 15:
            crafted_ct_blocks[-2] = '\x00' + crafted_ct_blocks[-2]
        
        crafted_ct = ''.join(crafted_ct_blocks)
        if len(crafted_ct)%16 !=0:
            raise Exception("You created string of length %d" %len(crafted_ct))
        try:
            pt = padding_oracle(crafted_ct)
            C.append(c)
        except Exception as e:
            # didnt find the right char
            continue
        
    if len(C) == 0:
        raise Exception('Failed to crack byte')
    return C


def chal3_17():
    ct = cbc_enc_one_string()
    crack_padding_oracle(ct)
    return


################
#################

# given a number (int) of value x
# convert it into a little endian binary of 64bit
# e.g 1 -> \x01\x00\x00...
def int2le(x):
    # turn x into a hex string of 64bits, 8 bytes, 16 hex chars
    x = format(x, '016x')
    # convert it to binary
    x = hexstr2bin(x)
    x = x[::-1]
    return x

# implement the aes ctr mode
# @params: key, is the key used for encryption,
#           nonce: a random number to be used ONCE with this key
#                   otherwise crypto will break
#           plint_text : text to be encrypted

def AES_CTR_ENC(key,nonce,plain_text):
    # create a stream of the key, stored in hex string format
    if len(nonce) != 8:
        raise exception("nonce must be 8 bytes")
    key_stream = ''
    n = len(plain_text)
    aes = AES.new(key, AES.MODE_ECB, '0')
    for j in range( n/16 + 1):
        key_stream += (aes.encrypt(nonce + int2le(j)) )
    if len(plain_text) > len(key_stream):
        raise Exception("Key is not long enough, need %d more bytes of key" %(len(plain_text)-len(key_stream)))

    key_stream = key_stream[:len(plain_text)]
    assert len(key_stream) == len(plain_text)
    ct = hexstr2bin(xor_string( bin2hexstr(key_stream), bin2hexstr(plain_text)))
    return ct


def AES_CTR_DEC(key,nonce,cipher_text):
    # create a stream of the key, stored in hex string format
    if len(nonce) != 8:
        raise exception("nonce must be 8 bytes")
    key_stream = ''
    n = len(cipher_text)
    aes = AES.new(key, AES.MODE_ECB, '0')
    for j in range( n/16 + 1):
        key_stream += ( aes.encrypt(nonce + int2le(j)) )
    if len(cipher_text) > len(key_stream):
        raise Exception("Key is not long enough, need %d more bytes of key" %(len(cipher_text)-len(key_stream)))

    key_stream = key_stream[:len(cipher_text)]
    assert len(key_stream) == len(cipher_text)
    pt = hexstr2bin(xor_string( bin2hexstr(key_stream), bin2hexstr(cipher_text)))
    return pt



def chal3_18():
    ct = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode('base64')
    pt = AES_CTR_DEC("YELLOW SUBMARINE", '\x00'*8, ct)
    print(pt)

#########################
### chal19
# breaking fixed nonce AES CTR


## reads a file and encrypts eveything
# under the same key and nonce
# each element is treated as a new plain text
def enc_same_nonce():
    key = gen_key(128/8)
    nonce = '\x00' * 8
    with open('19.txt','r') as f:
        txt = f.read()
    list_of_texts = txt.strip().split('\n')
    list_of_texts = map( lambda x: x.decode('base64'), list_of_texts)
    list_ct = list()
    for t in list_of_texts:
        list_ct.append( AES_CTR_ENC(key,nonce,t))
    return list_ct


def crack_same_nonce_CTR(list_ct):
    # assuming the text is normal english
    # I can rely on the fact that xor with space leads to lower <-> capital change
    # I can find the sapce -> key[byte]
    # arrane all the key[byte] together and we get the stream key
    
    # find the min length of the cipher texts
    N = max ( map(len,list_ct))
    print(N)
    N = min ( map(len,list_ct))
    N = 38
    print(N)
    ENGLISH_LETTERS = string.lowercase + string.uppercase + ' ' #+ ',.!?'
    stream_key = ['\x00']*N
    for j in range(N):
        xx = map (lambda x: x[j] if j<len(x) else '', list_ct)
        x = [el for el in xx if el!='']
        # see how many hits I get if I xor with something else
        score_list = list()
        for k in range(256):
            score = 0
            for c in x:
                if chr(ord(c) ^ k) in ENGLISH_LETTERS:
                    score += 1
                else:
                    score -= 100
            score_list.append( (score, chr(k)))
        stream_key[j] = max(score_list)[1]
    
    mKey = ''.join(stream_key)
    for ct in list_ct:
        dec_length = min ( len(mKey), len(ct))
        pt = hexstr2bin( xor_string(bin2hexstr (mKey[:dec_length]) , bin2hexstr(ct[:dec_length])) )
        print(repr(pt))
    print(repr(stream_key))


def chal3_19():
    list_ct = enc_same_nonce()
    crack_same_nonce_CTR(list_ct)


#################
## chal3.20
# break fixed nonce CTR using stats

def crack_same_nonce_stat(list_ct):
    # will break it by breaking the fixed key xor
    # need to convert the string to base64 and write it to a file
    FILE_PATH = 'tmp.txt'
    N = min ( map(len,list_ct))
    ct_list = map(lambda x: x[:N], list_ct)
    ct = ''.join(ct_list).encode('base64')
    with open(FILE_PATH,'w') as f:
        f.write(ct)
    break_repeat_xor(FILE_PATH)
    return


def chal3_20():
    list_ct = enc_same_nonce()
    crack_same_nonce_stat(list_ct)

##################################
## chal3.21
# MT19937 Mersenne Twister RNG

class MersenneTwisterRNG():
    def __init__(self,seed):
        self.w = 32
        self.n = 624
        self.index = self.n
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.ud = (11, 0xFFFFFFFF)
        self.sb = (7, 0x9D2C5680)
        self.tc = (15, 0xEFC60000)
        self.l = 18
        self.l32 = lambda x: x & 0xFFFFFFFF
        self.MT = [0] * self.n
        self.MT[0] = seed
        f = 1812433253
        for i in range(1,self.n):
            self.MT[i] = self.l32( f*( self.MT[i-1] ^  self.MT[i-1] >> self.w -2 ) + i )

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        # change the number
        y = self.MT[self.index]

        y = y ^ y >> self.ud[0] & self.ud[1]
        y = y ^ y << self.sb[0] & self.sb[1]
        y = y ^ y << self.tc[0] & self.tc[1]
        y = y ^ y >> self.l

        self.index += 1
        return self.l32(y)

    def twist(self):
        for i in range(self.n):
            # 
            x = self.l32((self.MT[i] & 0x80000000) + (self.MT[(i+1)%self.n] & 0x7fffffff))
            xA = x >> 1
            if ( x%2 == 1):
                xA = xA ^ self.a
            self.MT[i] = self.MT[ (i+self.m)%self.n] ^ xA
        self.index = 0


def chal3_21():
    rng = MersenneTwisterRNG(0)
    x = rng.extract_number()
    print("random number is:", x)

#####################
####### chal3.22
### crack seed

def chal3_22():
    delay = random.choice(range(1000))
    s = int(time.time())
    rng1 = MersenneTwisterRNG(s)
    r1 = rng1.extract_number()
    # sleep for delay
    #sleep(delay)
    #now = int(time.time())
    # don't want to wait, just emulate it
    now = s + delay

    for j in range(1000):
        rng2 = MersenneTwisterRNG(now-j)
        if rng2.extract_number() == r1:
            print("slept for %d secs" %j)
            print("Seed was:", now - j)
            return


###################
###### chal 3.23
### clone RNG from output

def untemper_left(y, mask, p):
    ''' undo the temper phase of rng where
    z = y ^ (y>>p & mask). This function find 
    y given mask, shift direction, shift number
    pass'''
    _int32 = lambda x: x & 0xFFFFFFFF
    b = lambda p: (1<<p) - 1
    
    x1 = 0
    x = [0]
    for j in range(0,33,p):
        yj = y & (b(p)<<j)
        mj = mask & (b(p)<<j)
        xj = yj ^ ( mj & (x[-1]<<p) )
        x.append(xj)
        x1 |= xj
        if _int32(b(p)<<j) == 0:
            break
    return _int32(x1)
    
def untemper_right(y, mask, p):
    x = [0]
    x1 = 0
    _int32 = lambda x: x & 0xFFFFFFFF
    b = _int32(int('1'*p +'0'*(32-p),2))
    for j in range(0,33,p):
        yj = y & ( b>>j )
        mj = mask & ( b>>j)
        xj = yj ^ (mj & x[-1]>>p)
        '''print("bits:",33-j,33-j-p)
        print("yj:",bin(yj))
        print("mj:",bin(mj))
        print("xj:",bin(xj))
        print('-'*10)'''
        x.append(xj)
        x1 |= xj
        if _int32(b>>j) == 0:
            break
    return _int32(x1)

def unit_test_untemper():
    X = [512, 0, 43, 512+43<<8]
    for x in X:
        y = x ^ (x>>7 & 0xEFC6000016)
        print(x,y)
        print(untemper_right(y,0xEFC6000016,  7))


def clone_MT19937(outputs):
    ''' given the outputs for a MT19937 rng,
    finds the internal state and clones it to another
    MT19937 RNG instance, so we can get the future'''

    # find the internal stare
    states = find_MT19937_internal_state(outputs)
    # init a new rng and set its states
    rogue_rng = MersenneTwisterRNG(0)
    rogue_rng.MT = states
    rogue_rng.index = 624
    return rogue_rng


def find_MT19937_internal_state(outputs):
    ''' given the outputs for a MT19937 rng,
    find the internal state, so that we can clone it'''
    #assert len(outputs) == 624

    # the transforms are
    #y := x ^ ((x >> u) & d); u,d = 11, 0xFFFFFFFF
    #y := y ^ ((y << s) & b); s,b = (7, 9D2C568016)
    #y := y ^ ((y << t) & c); t,c = (15, EFC6000016)
    #z := y ^ (y >> l);       l = 18

    f1 = lambda y: untemper_right(y, 0xFFFFFFFF, 11)
    f2 = lambda y: untemper_left(y, 0x9D2C5680,  7)
    f3 = lambda y: untemper_left(y, 0xEFC60000,  15)
    f4 = lambda y: untemper_right(y, 2**64-1, 18)
    
    output2state = lambda y: f1(f2(f3(f4(y))))
    states = map(output2state, outputs)

    return states

def clone_unit_test():
    rng1 = MersenneTwisterRNG(0)
    L = list()
    for i in range(624):
        L.append(rng1.extract_number())
    #print('rnd:',L[:])
    orgStates = rng1.MT
    clStates = clone_MT19937(L)
    print (all([clStates[i] == orgStates[i] for i in range(624)]))

def chal3_23():
    rng1 = MersenneTwisterRNG(11182410)
    rogue_rng = MersenneTwisterRNG(0)
    x = []
    for i in range(624):
        x.append(rng1.extract_number())
    rogue_rng = clone_MT19937(x)
    for i in range(624):
        if ( rogue_rng.extract_number() != rng1.extract_number()):
            print("Error in cloning MT19937")
            return
    print("Successfully cracked MT19937")
    return

###############
##### chal 3.24
# PRNG cipher and breaking it
class CipherMT19937():
    def __init__(self,key):
        # 16 bit key as seed
        self.seed = key & 0xFFFF

    def expand_key(self, plain_text):
        self.Rng = MersenneTwisterRNG(self.seed)
        enc_key = [ self.Rng.extract_number() for i in range( len(plain_text)/8 + 1) ]
        enc_key = ''.join(map(lambda x: hex_clean(hex(x)), enc_key ))
        assert len(enc_key)>=len(plain_text)
        enc_key = enc_key[:len(plain_text)]
        return enc_key

    def encrypt(self, plain_text):
        plain_text = binascii.hexlify(plain_text)
        key = self.expand_key(plain_text)
        assert len(key) == len(plain_text)
        # need to specify block size in bytes
        cipher_text = xor_string(key,plain_text,block_size=len(key)/2 )
        cipher_text = binascii.unhexlify(cipher_text)
        return cipher_text

    def decrypt(self, cipher_text):
        # decryption is exact reverse of enc
        return self.encrypt(cipher_text)


def unit_test_CipherMT19937():
    x = CipherMT19937(14)
    plain_text = 'Ikava ihollesi'
    print(x.decrypt(x.encrypt(plain_text)))

def crack_MT19937_cipher():
    # get a cipher text back
    key = ord(gen_key(1)) + ord(gen_key(1))<<8
    print("org key is:",key)
    C = CipherMT19937(key)
    plain_text = 'a'*14
    ct = C.encrypt( random.choice(range(4,20))*'M' + plain_text)

    ## now let's find the key
    prefix_len = len(ct) - 14
    crafted_pt = prefix_len*'\0' + 'a'*14
    # brute force it
    keys = list()
    for s in range(2**16):
        C2 = CipherMT19937(s)
        if C2.encrypt(crafted_pt)[-10:] == ct[-10:]:
            print("key is:",s)
            keys.append(s)
    print(keys)

def chal3_24():
    crack_MT19937_cipher()


################

if __name__ == "__main__":
    #chal3_17()
    #chal3_18()
    #chal3_19()
    #chal3_20()
    #chal3_21()
    #chal3_22()
    #chal3_23()
    chal3_24()


