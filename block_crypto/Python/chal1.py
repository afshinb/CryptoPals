#!/usr/bin/python
from __future__ import print_function
import binascii
from time import sleep
from Crypto.Cipher import AES

###################
### Helpers

englishLetterFreq = {'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25 \
 ,'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, \
 'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07, ' ':1, '.':1, ',':1}

# x is hex string, y is a hex string, x="1a98" x^y is also a string
def fixed_xor_string(x,y):
    x = hex_clean(x)
    y = hex_clean(y)
    if len(x) != len(y):
        raise Exception('unequal string length for xor')
    z = hex_clean(hex(int(x,16)^int(y,16)))
    # drop the L at the end if it is there
    return z

# given a string x drop the 0x from the beggining
def hex_clean(x):
    if x.endswith("L"):
        x = x[:-1]
    if x.startswith("0x"):
        x = x[2:]
    if len(x) % 2 != 0:
        x = '0'+ x
    return x

def read_English_words():
    with open("../wordsEn.txt","r") as f:
        L = f.read().split()
        s = set(L)
    return s
        

# create a statics of characters
def character_stat(s):
    stats = dict()
    set_char = set(s)
    for c in set_char:
        stats[c] = 100.0 * s.count(c) / len(s)
    return stats
    

def histogram_score(s):
    s = s.lower()
    str_stat = character_stat(s)
    score = 0
    all_chars = set(s).union(englishLetterFreq.keys())
    for c in all_chars:
        if c not in str_stat:
            score += (englishLetterFreq[c])**2
        elif c not in englishLetterFreq.keys():
            score += 100000
        else:
            score += (englishLetterFreq[c] - str_stat[c])**2
    return -1.0 * score / len(s)

# give a score to string based on etaoin shrdlu
def simple_scoring(s):
    common_chars = 'etaoin shrdlu'
    counter = 0
    for c in common_chars:
        counter += s.count(c)
    return 1.0*counter/len(s)

def simple_scoring2(s):
    counter = 0
    for c in s:
        if c.isalpha():
            counter += 1
        else:
            counter -= 1
    return 1.0*counter/len(s)

##################



#1.1 hex to base 64
def h2b64(s):
    return s.decode("hex").encode("base64").strip()

#1.2 fixed length xor
def fixed_xor(x,y):
    return x^y


#1.3 decipher a single-byte XOR cipher fixed b
def sb_xor_cipher(s):
    string_length = len(s)/2
    english_dict = read_English_words()
    ans = list()
    for k in range(128):
        #sleep(0.1)
        key = hex_clean(hex(k)) * string_length
        text = fixed_xor_string(key, s)
        #print("\r"+(text),end="")
        text = binascii.unhexlify(hex_clean(text))
        words = text.split(' ')
        #print("\r\b" + k*"*", end="")
        for w in words:
            if w in english_dict:
                ans.append((text,k))
                break
    #print()
    #print(ans)
    return ans



#1.3 decipher a single-byte XOR cipher fixed b
def sb_xor_cipher2(s):
    string_length = len(s)/2
    english_dict = read_English_words()
    ans = list()
    for k in range(128):
        #sleep(0.1)
        key = hex_clean(hex(k)) * string_length
        text = fixed_xor_string(key, s)
        #print("\r"+(text),end="")
        text = binascii.unhexlify(hex_clean(text))
        ans.append((simple_scoring(text),text))
    
    #print(max(ans))
    return ans



# 1.4 find the string encrypted with single byte XOR
def detect_single_character_xor(file_address):
    with open(file_address,'r') as f:
        lines = f.readlines()
    for l in lines:
        enc_str = l.strip()
        plain_text = sb_xor_cipher(enc_str)
        if len(plain_text) > 0:
            print(plain_text)
    return


# 1.5 repeating key XOR
# plain text is ascii character, key is ascii too
def repeat_key_XOR(plain_text, key):
    str_length = len(plain_text)
    key_length = len(key)
    print(str_length, key_length)
    expanded_key = key * (str_length/key_length)
    if len(expanded_key) != len(plain_text):
        expanded_key += key[:len(plain_text)-len(expanded_key)]
    print(expanded_key)
    print(plain_text)
    str2bin = lambda x: int(binascii.hexlify(x),16)
    cipher_text = str2bin(expanded_key) ^ str2bin( plain_text)
    print( hex(cipher_text))

####################################
#__________________________________
## 1.6
## break repeating key xor
###################################

# count the number of bits that are different in two strings
def hamming_distance(x,y):
    str2bin = lambda x: int(binascii.hexlify(x),16)
    return bin(str2bin(x) ^ str2bin(y)).count('1')

# transpose text of m k block sizes to k blocks of size m
def transpose_block(text, k):
    # pad the text to be multiple of k
    if len(text)%k != 0:
        text = text + '0'*(len(text)%k)
    chunks = list()
    for j in range( len(text)/k):
        chunks.append( text[j*k:(j+1)*k] )
    get_ith_byte = lambda x,i: x[2*i:2*i+2]
    transposed_text_blocks = list()
    for i in range(k/2):
        transposed_text_blocks.append([ get_ith_byte(chunk, i) for chunk in chunks])
    transposed_text = list()
    for item in transposed_text_blocks:
        transposed_text.append((''.join(item)))
    return transposed_text

#print(transpose_block("071122334455",4))

# gets two hex strings and returns a hex string
def decrypt(key,ct):
    ct = hex_clean(ct)
    key = hex_clean(key)
    expanded_key =  key * (len(ct)/len(key))
    if len(expanded_key) != len(ct):
        expanded_key += key[:len(ct)-len(expanded_key)]
    pt = fixed_xor_string(expanded_key, ct)
    pt = binascii.unhexlify(hex_clean(pt))
    return pt

def break_repeat_xor(file_path):
    with open(file_path,'r') as f:
        cipher_text = f.read()
    # convert b64 to hex
    ct = cipher_text.decode('base64').strip().encode('hex')
    ct = hex_clean(ct)
    # find the smallest edit distance
    edit_distance = list()
    for keysize in range(2,80,2):
        x1=ct[:keysize]
        x2=ct[keysize:2*keysize]
        edit_distance.append( (1.0*hamming_distance(x1,x2)/keysize , keysize))
    edit_distance.sort()
    plain_texts = list()
    for _,keysize in edit_distance:
        # tranpose the block to align all the characters enc with the same key
        print("Trying keysize:",keysize)
        tr_txt = transpose_block(ct, keysize)
        key_max = 256
        KEY = list()
        # find one byte of the key
        for block in tr_txt:
            (best_score, best_key, best_pt) = (float('-inf'),0,'0')
            for key in range(0, key_max):
                expanded_key = hex_clean(hex(key)) * (len(block)/2)
                plain_text = fixed_xor_string(expanded_key, block)
                plain_text = binascii.unhexlify(hex_clean(plain_text))
                best_score, best_key, best_pt = max( (best_score,best_key,best_pt), \
                    (histogram_score(plain_text), key, plain_text) )
            #print(best_pt, best_score)
            KEY.append(hex_clean(hex((best_key))))
        #print(''.join(KEY))
        # decrypt with key
        # decrypt first two sentences
        cipher_key = ''.join(KEY)
        pt = decrypt(cipher_key, ct)
        plain_texts.append( (histogram_score(pt), pt, cipher_key))
    plain_texts.sort()
    print(plain_texts[-1])
    return
            

#####################################
#####################################
## 1.7 Decryptin AES in EBC mode

def AES_ECB_decrypt(key,cipher):
    # EBC doesnt use IV
    return AES.new(key, AES.MODE_ECB, '0').decrypt(cipher)

def chal7(file_path):
    with open(file_path,'r') as f:
        ct = f.read()
    # decode cipher text from base64
    ct = ct.decode('base64')
    print(AES_ECB_decrypt("YELLOW SUBMARINE", ct))
    return

############
### 1.8 detect AES in ECB mode

def detect_ECB(file_path):
    with open(file_path,'r') as f:
        ct = f.read()
    list_of_ct = ct.strip().split('\n')
    for ct in list_of_ct:
        score  = ECB_score(ct)
        if score > 0:
            print (ct,score)
    return

# how likely is it that this is a cipher text enc by ECB
def ECB_score(ct):
    #1 can use hamming distance
    #2 see if they are the same
    n = len(ct)/32 # number of blocks for 128bit key
    blocks = list()
    for i in range(n):
        blocks.append(ct[ 32*i: 32*(i+1)])

    # check if a string is repeated again
    blocks_set = set(blocks)
    return len(blocks)-len(blocks_set)

#####################################
#####################################
#####################################
#####################################

### mini test
read_English_words()

###

if __name__ == "__main__":
    '''a1 = h2b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    assert a1 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    a2 = fixed_xor(int("1c0111001f010100061a024b53535009181c",16),int("686974207468652062756c6c277320657965",16))
    a2 = fixed_xor_string("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")
    sb_xor_cipher2("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print('-'*30)
    detect_single_character_xor("4.txt")
    print('-'*30)
    repeat_key_XOR("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", "ICE")
    repeat_key_XOR("afshin_2b@yahoo.com","ICE")
    repeat_key_XOR("sec@P@33w0rd", "ICE")
    print('-'*30)
    assert 37 == hamming_distance("wokka wokka!!!","this is a test")
    break_repeat_xor('6.txt')
    chal7('7.txt')'''
    detect_ECB('8.txt')

