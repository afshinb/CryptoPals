#!/usr/bin/python
import binascii
from Crypto.Cipher import AES
import os
import random

def hex_clean(x):
    if x.endswith("L"):
        x = x[:-1]
    if x.startswith("0x"):
        x = x[2:]
    if len(x) % 2 != 0:
        x = '0'+ x
    return x

# two hex strings x,y returns hex string z
def xor_string(x,y):
    str2bin = lambda a: int(a,16)
    z = str2bin(x) ^ str2bin(y)
    return hex_clean(hex(z))

# generate a key of size n bytes
def gen_key(n):
    return os.urandom(n)

###########
### chal 2.9
# @param: pad_size is the block size in bytes
def pkcs7_pad(txt, block_size):
    if block_size >= 256:
        raise Exception("pad size is more than 256")
    p = block_size - (len(txt) % block_size)
    pad_char = binascii.unhexlify(hex_clean(hex(p)))
    txt = txt + (p*pad_char)
    return txt

####################
### chal 2.10


## break text into blocks of the given size
def create_blocks(txt, size):
    if len(txt)%size != 0:
        raise Exception("text is not properly padded. len(txt)=%d, size=%d" %(len(txt) ,size))
    L = list() 
    for i in range( len(txt)/size):
        L.append( txt[i*size:(i+1)*size] )
    return L

#print(create_blocks("YELLOW SUBMARINE",4))

# AES encrypt with CBC mode
# is key, IV, plain_text hex or string or what?!
# key is binary 
# plain text is treated as binary too
def AES_encrypt(key, IV, plain_text):
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
def AES_decrypt(key, cipher_text):
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
        

def dec_test(file_path):
    with open(file_path,'r') as f:
        ct = f.read()
    ct = ct.decode('base64')
    y = AES_decrypt("YELLOW SUBMARINE",ct)
    print(y)
    return
#####################
## Chal 2.11, ECB/CBC detection oracle
def encrypt_ECB_CBC(plain_text):
    key = gen_key(128/8)
    IV = gen_key(128/8)
    AES_CBC = lambda key,IV,plain_text:AES_encrypt(key,IV, plain_text)
    AES_ECB = lambda key,IV,plain_text: AES.new(key,AES.MODE_ECB,'0').encrypt(pkcs7_pad(plain_text,128/8))
    encrypt_funcs = [AES_CBC, AES_ECB]
    i = random.choice([0,1])
    print ("Choosing i=%d" %i)
    return encrypt_funcs[i](key,IV,plain_text)

# adds some random string to the begin and
# end of pt before encryption
def add_to_pt(pt):
    n = random.choice(range(5,11))
    return gen_key(n) + pt + gen_key(n)

# function that detects if an encryption black box is
# CBC or ECB
def ECB_CBC_ORACLE():
    plain_text = 'a'*128
    plain_text = add_to_pt(plain_text)
    ct = encrypt_ECB_CBC(plain_text)
    ct_blocks = create_blocks(ct, 128/8)
    if len(ct_blocks) == len(set(ct_blocks)):
        print("CBC")
    else:
        print("ECB")
    
####################
# chal 2.12
X_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode("base64")
GLOBAL_KEY = gen_key(128/8)
GLOBAL_IV = gen_key(128/8)

# encrypt pt under 128 bit key in ECB mode
def AES_128_ECB(key,pt):
    aes = AES.new(key, AES.MODE_ECB, '0')
    return aes.encrypt(pkcs7_pad(pt,128/8))

#
def find_ECB_block_size(enc_func):
    x = len(enc_func(GLOBAL_KEY,'a'))
    bin2hexStr = lambda x: binascii.hexlify(x)
    for n in range(2,1024):
        if x != len(enc_func(GLOBAL_KEY,'a'*n)):
            return n
    raise Exception("block_size bigger than 1024bytes")


# 
def crack_1byte(known_str, unknown_str):
    if len(known_str)%16 != 15:
        raise Exception("can only guess 1 byte")
    ct = AES_128_ECB(GLOBAL_KEY, known_str + unknown_str)
    # only keep the first block
    # find which block is of interest
    index = len(known_str)/16
    ct = ct[16*index:16*(index+1)]
    for i in range(256):
        c = binascii.unhexlify(hex_clean(hex(i)))
        if ct == (AES_128_ECB(GLOBAL_KEY, known_str + c))[16*index:16*(index+1)]:
            return c
    raise Exception("Could not find the key :(")


# decrypt one byte at a time. Decrypts X_string
def decrypt_1_byte():
    block_size = 16
    a = 'a'
    decrypted_str = ''
    N = len(X_STRING)
    for i in range(1,N):
        known_str = (15-len(decrypted_str)%16)*a + decrypted_str
        assert len(known_str)%16 == 15
        c = crack_1byte(known_str , X_STRING[i-1:])
        decrypted_str += c
    print decrypted_str

####################
## chal 2.13
# fake admin

def profile_for(email):
    # clean & or =
    email = email.replace('&','')
    email = email.replace('=','')
    p = "email=%s&uid=10&role=user" %email
    return p

def oracle(email):
    # use the global key for encryption
    pt = profile_for(email)
    ct = AES_128_ECB(GLOBAL_KEY,pt)
    return ct

def check_213(ct):
    aes = AES.new(GLOBAL_KEY, AES.MODE_ECB, '0')
    pt = aes.decrypt(ct)
    return (pt.strip())


def fake_admin():
    # forge an account with admin prev
    # sanity check
    #print(repr(check_213(oracle("kings never die"))))
    
    #    123456789abcdf    123456789abcdf   123456789abcdf
# target:email=x@x.com     &uid=10&role=    admin--------       - is padding
# pt1:   email=xxxxxxx     admin---------   &uid=10&role=user       # get the second block put it last
# pt2:   email=my_email    a&uid=10&role=   user                    # get the first two blocks and put them first
    email1 = 'a'*(16-len('email=')%16) + 'admin' + '\x0b'*11
    ct1 = oracle(email1)
    email2 = (16-len('email=&uid=10&role=')%16)*'a'
    ct2 = oracle(email2)
    # forge the cipther text
    # remove last block of ct2 and replace it with second block of ct1
    forged_ct = ct2[:-16] + ct1[16:32]
    print(repr(check_213(forged_ct)))

#######################
## chal2.14
# byte at a time ECB decryption with random-prefix
#################

# create a random prefix then encrypt with EBC)
def AES_128_ECBRP(pt):
    n = random.choice(range(16))
    prefix = gen_key(n)
    pt = prefix + pt
    return AES_128_ECB(GLOBAL_KEY,pt)

# assume we know block size is 16

# gives a string that lets us find how many bytes were prepended before
# block_size is the number of bytes in each block
def instrumentation_string(block_size):

    # construct a string like this, for blocks of size 4
    # 0000 0000 0000 000Y 0000 00YY 0000 0YYY

    # We will always have block of all 0s, depending on the number of bytes
    # of the prefix, we will get a block of all 0s at a given position

    # reference block, will always have a all 0 block
    # there are redundancies to help us make sure this is our block
    # it would repeat itself
    s = '0'*2*block_size
    for j in range(block_size):
        s += ('0'*block_size) + ('0'*(block_size-j) + 'Y'*j)
    s += '0'*block_size     # to check if random pad is 0 or block_size-1
    if len(s)%block_size != 0:
        raise Exception("Created malformed instrumentation string, it has length %d" %len(s))
    return s


# find the random prefix
def find_rand_pad(ct,block_size):
    # our master block is when we see the same block 3 times in a row
    ct_blocks = create_blocks(ct,block_size)
    master = None
    msg_start_block = None
    for i,cipher in enumerate(ct_blocks):
        # if we get 3 ct that are equal in a row we have found our
        # master string
        if i+2 >=len(ct_blocks):break
        if ct_blocks[i] == ct_blocks[i+1] == ct_blocks[i+2]:
            master = ct_blocks[i]
            msg_start_block = i
            break
    if not master:
        raise Exception("Could not find the master")
    # continue scanning the blocks until we hit a 
    # two consecutive block where the master hasnt occured
    N = len(ct_blocks)
    current = None
    bin2hexStr = lambda x: binascii.hexlify(x)
    prev = None
    for j in range(msg_start_block,N-1):
        #print(bin2hexStr(ct_blocks[j]))
        #print(bin2hexStr(ct_blocks[j+1]))
        if ct_blocks[j] == master or ct_blocks[j+1] == master:
            continue
        else:
            return ((j-msg_start_block-2)/2)%block_size
    raise Exception("Failed to find the number of random pads")


### try to crack a single byte at a time
# would work if the oracle adds 1 byte of padding
def crack_a_byte_chance(known_str, unknown_str):
    if len(known_str)%16 != 15:
        raise Exception("can only guess 1 byte")
    ins_str = instrumentation_string(128/8)
    n=0
    # junk_pad so that if the oracle adds 8 bytes we get complete block
    # we will be in luck when oracle adds 8 byte of padding
    junk_pad = 8*'a'
    while n != 8:
        #print(ins_str + junk_pad + known_str + unknown_str )
        ct = AES_128_ECBRP(ins_str + junk_pad + known_str + unknown_str)
        n = find_rand_pad(ct, 128/8)
    # now we have a byte aligned string!
    # find the block of interest
    num_unknown_str_blocks = (len(unknown_str)-1)/16
    # last block is just padding
    index = -1 - num_unknown_str_blocks
    CT0 = ct[16*(index-1):16*index]

    # find the encrypted byte
    # let's just take chances to get the desired num of padding
    for c in range(256):
        n = 0
        x = binascii.unhexlify(hex_clean(hex(c)))
        while n!=8:
            ct = AES_128_ECBRP(ins_str + junk_pad + known_str + x )
            n = find_rand_pad(ct, 128/8)
        CT1 = ct[-32:-16]
        if CT1 == CT0:
            # found the enc byte
            print(x)
            return x
    raise Exception("Failed to find the enc byte")

def chal2_14():
    #c = crack_a_byte_chance('a'*15 , 'b'*17)
    block_size = 16
    a = 'a'
    decrypted_str = ''
    N = len(X_STRING)
    for i in range(1,N):
        known_str = (15-len(decrypted_str)%16)*a + decrypted_str
        assert len(known_str)%16 == 15
        c = crack_a_byte_chance(known_str , X_STRING[i-1:])
        decrypted_str += c
        print(c)
    print decrypted_str

#################
######### chal2.15
### padding validation

# validate pkcs7 pad is valid
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

def test_2_15():
    strings = ["ICE ICE BABY\x04\x04\x04\x04","ICE ICE BABY\x05\x05\x05\x05","ICE ICE BABY\x01\x02\x03\x04"]
    for s in strings:
        try:
            print(remove_pkcs7_pad(s,16))
        except Exception as e:
            print(e)
    return

############
### chal 2.16
# CBC bit flipping attack

def CBC_ENC(pt):
    pt = pt.replace(';','";"')
    pt = pt.replace('=','"="')
    pt = "comment1=cooking%20MCs;userdata=" + pt + ";comment2=%20like%20a%20pound%20of%20bacon"
    key = GLOBAL_KEY
    ct = AES_encrypt(key, GLOBAL_IV, pt)
    return ct

# decrypt ct with cbc aes and check if admin=true is there
def CBC_DEC(ct):
    pt = AES_decrypt(GLOBAL_KEY, ct)
    # check if it is admin
    if ';admin=true;' in pt:
        print("Granting Admin previliges")
    else:
        print("User mode")
    return

# create a cipher text that has
# ;admin=true; when decrypted
def forge_admin_ct():
    # bit flipping: x ^ C -> ;  67
    #               x ^ E -> =  69
    target_string = 'xadminxtruexletmein'
    ct1 = CBC_ENC(target_string)
    bin2hexStr = lambda x: binascii.hexlify(x)
    hexStr2bin = lambda x: binascii.unhexlify(x)
    # we will flip bytes 0,6,11
    flip = lambda x,y: hexStr2bin(xor_string(bin2hexStr(x),bin2hexStr(y)))
    a = flip(ct1[32],'C')
    b = flip(ct1[32+6],'E')
    c = flip(ct1[32+11],'C')
    ct = list(ct1)
    ct[32] = a
    ct[32+6] = b
    ct[32+11] = c
    ct = "".join(ct)
    CBC_DEC(ct)


#####################

if __name__ == "__main__":
    #print(repr(pkcs7_pad('YELLOW SUBMARINE',20)))
    #print(repr(AES_encrypt("YELLOW SUBMARINE", '\x00'*16, "SOME RANDOM TEXT is HERE")))
    X=(AES_encrypt("YELLOW SUBMARINE", '\x01'*16, "SOME RANDOM TEXT is here!" ))
    #print(len(X))
    #print(repr(AES_decrypt("YELLOW SUBMARINE", X)))
    #dec_test('10.txt')
    #print("ECB/CBC ORACLE:")
    #ECB_CBC_ORACLE()
    #print(find_ECB_block_size(AES_128_ECB))
    #decrypt_1_byte()
    #fake_admin()
    #chal2_14()
    #test_2_15()
    forge_admin_ct()



