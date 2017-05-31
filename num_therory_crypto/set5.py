#!/usr/bin/python

'''challenge set 5 from cryptopals.com
challenge 33-40'''
import random
import os
from crypto_math import *
from hashlib import sha256
from Crypto.Cipher import AES
import hmac
import rsa
import math

class Diffie_Hellman():
    def __init__(self,p,g):
        '''p is the prime and g is the generator'''
        self.p = p
        self.g = g
        self._secret = None
    
    def set_sk(self,a):
        '''secret key for DH'''
        self.secret = a

    def get_pk(self):
        return modexp(self.g, self.secret, self.p)

    def _shared_secret(self,pk):
        '''generate the shared secret given Bob's public key'''
        self._secret = modexp(pk, self.secret, self.p)

    def get_keys(self,pk):
        '''derive AES key and MAC key using SHA-256 of shared secret'''
        if self._secret == None:
            self._shared_secret(pk)
        secret = self._secret
        secret = "{0:0{1}x}".format(secret,32)   #256 bit number
        keys = hex2bin(sha256(secret).hexdigest())
        return (keys[:128/8],keys[128/8:])



NIST_P = """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff""".replace('\n','')
NIST_P = int(NIST_P,16)
NIST_G = 2


def chal33():
    '''(p,g) = (37,5)
    a_sk = 70
    b_sk = 29'''
    # generate two random numbers 1024 bits
    a_sk = bin2int(os.urandom(1024/8))
    b_sk = bin2int(os.urandom(1024/8))
    p = NIST_P
    g = NIST_G

    Alice = Diffie_Hellman(p,g)
    Bob = Diffie_Hellman(p,g)
    Alice.set_sk(a_sk)
    Bob.set_sk(b_sk)

    # share public keys:
    pkAlice = Alice.get_pk()
    pkBob = Bob.get_pk()

    # Alice derives the key based on secret
    k1 = Alice.get_keys(pkBob)

    # Bob derives the key based on secret

    k2 = Bob.get_keys(pkAlice)

    # establish the shared keys are the same
    assert k1 == k2

################################
######## Chal 34
# MITM key-fixing attack on DH
def chal34():
    p = NIST_P
    g = NIST_G
    a_sk = bin2int(os.urandom(1024/8))
    b_sk = bin2int(os.urandom(1024/8))

    Alice = Diffie_Hellman(p,g)
    Bob = Diffie_Hellman(p,g)
    Alice.set_sk(a_sk)
    Bob.set_sk(b_sk)

    # share public key
    # Man in the middle attack happens here
    pkAlice = Alice.get_pk()
    pkBob = Alice.get_pk()
    
    # MITM
    pkAlice = p
    pkBob = p
    ########

    ka = Alice.get_keys(pkBob)
    kb = Bob.get_keys(pkAlice)

    # mallory is man in the middle 
    # changed the public keys with p -->
    # p **x mod p -> 0 
    # the shared_secret is 0
    Mallory_secret = 0
    secret = "{0:0{1}x}".format(Mallory_secret,32)   #256 bit number
    keys = hex2bin(sha256(secret).hexdigest())
    km = (keys[:128/8],keys[128/8:])

    # Mallory has the same key as alice and bob
    assert km == ka == kb


    # Alice sends Hello to Bob
    iva = os.urandom(128/8)
    aesAlice = AES.new(ka[0],AES.MODE_CBC,iva)
    ct = aesAlice.encrypt("YELLOW SUBMRAINE")


    # Alice sends back the same msg to Bob
    ivb = os.urandom(128/8)
    aesBob = AES.new(kb[0],AES.MODE_CBC,iva)
    Bob_pt = aesBob.decrypt(ct)

    # Mallory can see the message
    aesMallory = AES.new(km[0],AES.MODE_CBC,iva)
    Mallory_pt = aesMallory.decrypt(ct)

    assert Mallory_pt == Bob_pt


###############################
###### Chal 35
# Implement DH with negotiated group
def DH_negotiatedGroup(tamper):
    '''MITM attack on DH with negotiated group
    @params: tamper, a function that tampers g'''
    
    # Alice and bob generate secret keys
    a_sk = bin2int(os.urandom(1024/8))
    b_sk = bin2int(os.urandom(1024/8))

    pA = NIST_P
    gA = NIST_G

    Alice = Diffie_Hellman(pA,gA)
    Alice.set_sk(a_sk)
    pkA = Alice.get_pk()
    
    # Alice sends Bob p,g
    # Bob gets p,g
    # g can be subject to tampering by MITM
    pB = pA
    # g is a function of p and original g in non tamper case
    gB = tamper(gA,pA)

    # MITM attack on negotiated group
    if tamper(30,40) == 30:
        # no tamper -> no MITM
        print("no MITM attack")
    elif tamper(30,40) == 1:
        # A's public key is 1
        # g = 1 attack,
        # g**b % p = 1 -> shared secret is 1
        Mallory = Diffie_Hellman(pA,gA)
        Mallory._secret = 1
        keyM = Mallory.get_keys(pkA)    # arbitrary pk
        pkA = 1                         # change Alice PK for Bob

    elif tamper(30,40) == 40:
        # g = p attack 
        # p mod p is zero so shared secret is 0
        Mallory = Diffie_Hellman(pA,gA)
        Mallory._secret = 0
        keyM = Mallory.get_keys(pkA)    # arbitrary pk
        pkA = 0                         # change Alice PK fr=ir Bob
    
    if tamper(30,40) == 39:
        # g =p-1 attack
        # g mod p is -1
        # shared_secret is either 1 or -1
        
        # legendre symbol doesnt help with parity of Alice's sk
        '''
        # check the parity of Alice sk using Legendre symbol
        if Legendre_sym(pkA,pA) != 1:
            # The secret key cannot be even
            pkA = pA - 1 
            print(a_sk)
            print("odd secret key")
        else:
            # the secret key can be even but not necessarily ?!
            # pkA has a square root but is it necessarily created by our g?
            # probably yes, if g is a generator of that group
            # not true, can find examples where above does not hold
            pkA = 1
            print(a_sk)
            print("even secret key")
        '''
        ''' there are two options,
        1 - assume the shared secret will be 1
            will work only 50% of the times
            the key exchange will fail because Alice and Bob end up
            with different keys
        2 - Act as man in the middle and have a key for talking to Alice
            and a different key for talking to Bob
            Let's implement 2nd approach
        '''
        ''' Shared secret is (-1) ** (a*b)
            pkA is changed to be -1 --> Bob secret = (-1) ** b  
            pKB is going to be (-1) ** b, so Bob's secret is his PK
            Alice's secret is going to be (pkB) ** a
                if pkB == 1:
                    Alice's shared secret is 1
                if pkB == -1:
                    Alice's shared secret can be +1 or -1
            Thus we will tell Alice Bob's PK is 1 and thus her shared secret will be 1
        '''
        ''' we could have guessed the parity of Alice's key if the generator used in the group
        was not a QR itself
        2 ** (p-1)/2 % p == 1   ----> cannot guess if a is odd or even because:
            A = 2**a  , A ** (p-1) / 2 = (2** (p-1)/2) ** a = 1 ** a -> is always 1
            Cannot detect the parity!
            '''
        
        if modexp(gA,(NIST_P - 1)/2 , NIST_P) == 1:
            print("The generator g = %d is a QR in the current prime group. Cannot determine parity of Alice's secret key" %gA)
            print("The value of generator is not suitable for DH but whatever!")
        pkA = pA - 1

    Bob = Diffie_Hellman(pB,gB)
    Bob.set_sk(b_sk)
    pkB = Bob.get_pk()

    if tamper(30,40) == 39:
        # continue MITM attak for g = p-1
        # change Bob's PK to be 1 when giving it to Alice
        # Bob's secret is his PK
        Mallory = Diffie_Hellman(pA,gA)
        Mallory._secret = pkB
        # key for Mallory-Bob session
        keyMB = Mallory.get_keys(0)    # arbitrary pk
        pkB = 1
        Mallory = Diffie_Hellman(pA,gA)
        Mallory._secret = 1
        # Mallory Alice session key
        keyMA = Mallory.get_keys(0)


    ######## exchange public keys and derive keys ######
    
    keyA = Alice.get_keys(pkB)
    keyB = Bob.get_keys(pkA)
    if tamper(30,40) == 30:
        assert keyA == keyB
    
    elif tamper(30,40) == 1:
        assert keyA == keyB == keyM
        print("MITM attack with g=1 works")

    elif tamper(30,40) == 40:
        assert keyA == keyB == keyM
        print("MITM attack with g=p works")
    elif tamper(30,40) == 39:
        assert keyA == keyMA
        assert keyB == keyMB
        print("MITM attack with g=p works")
    #### keys are the same so we can communicate with AES #####
    # skip implementing them

def Legendre_sym(x,p):
    return modexp(x, (p-1)/2, p)

def chal35():
    tamper_f = [ lambda g,p: g , lambda g,p: 1, lambda g,p: p , lambda g,p:p-1 ]
    for f in tamper_f:
        DH_negotiatedGroup(f)


########################
#### Chal36
# Implement Secure Remote Password

class SRPServer():
    '''class implementing a secure remote password server'''
    def __init__(self,N,g,k,email,passwd):
        self.n  = N
        self.g = g
        self.k = k
        self.email = email
        self.passwd = passwd
        # 256 bit salt
        self.salt = os.urandom(256/8)
        self.secret = bin2int(os.urandom(256/8)) % self.n
        self.v = 0

    def gen_v(self):
        '''generate v = g **x %N, x = SHA256(salt || passwd)'''
        x = int(sha256(self.salt + self.passwd).hexdigest(),16)
        self.v = modexp(self.g, x, self.n)
        # get rid of x
        del x
        return self.v
    
    def get_B(self):
        '''get B = kv + g**b % N'''
        self.B = (self.k*self.v + modexp(self.g, self.secret, self.n)) % self.n
        return self.B

    def get_salt(self):
        return self.salt
    
    def pair_with(self,pk):
        '''specify the client's public key'''
        self.A = pk
    
    def get_shared_key(self):
        u = int(sha256(str(self.A) + str(self.B)).hexdigest(), 16)
        S = modexp(self.A * modexp(self.v, u , self.n) , self.secret , self.n)
        print("Server:",S)
        self.shared_key = sha256(str(S)).digest()
        return self.shared_key

    def get_HMAC(self):
        '''get the hmac of salt with the shared key'''
        h = hmac.new(self.shared_key)
        h.update(self.salt)
        return h.hexdigest()


class SRPClient():
    '''class implementing a secure remote password client'''
    def __init__(self, N, g, k, email, passwd):
        self.n = N
        self.g = g
        self.secret = bin2int(os.urandom(256/8)) % self.n
        self.PK = modexp(g, self.secret, N)
        self.k = k
        self.email = email
        self.passwd = passwd

    def get_shared_key(self):
        '''get the shared key for the protocol'''
        u = int(sha256(str(self.PK) + str(self.B)).hexdigest(), 16)
        x = int(sha256(self.salt + self.passwd).hexdigest(),16)
        S = modexp( (self.B - self.k * modexp(self.g ,x, self.n)), self.secret + u * x, self.n)
        self.shared_key =  sha256(str(S)).digest()
        return self.shared_key

    def set_server_id(self, salt, B):
        '''specify the salt, B value for the server'''
        self.salt = salt
        self.B = B


    def get_Hmac(self):
        '''return the HMAC to be sent to server
        HMAC(K,salt) '''
        h = hmac.new(self.shared_key)
        h.update(self.salt)
        return h.hexdigest()


def secure_remote_passwd(email,passwd,rogue_client = None, rogued_shared_key=None):
    ''' implement a remote secure password protocol
    Client and server both know email and password
    they want to exchange it safely so that Eve cannot 
    pick up any information which help her break the passwd'''

    # Agree on N,g,k, email, passwd
    N = NIST_P
    g = 2
    k = 3 

    server_email = 'vlad@yandex.ru'
    server_passwd = 'abc123'    # the password as stored on the server side
    server = SRPServer(N,g,k,server_email,server_passwd)
    client = SRPClient(N,g,k,email,passwd)

    # for chal37 when client is rogue
    if rogue_client != None:
        print("breaking SRP")
        client = rogue_client
    server.gen_v()

    print('''C->S
    Send I, A=g**a % N (a la Diffie Hellman)''')
    email_c2s , pkClient = email, client.PK 
    server.pair_with(pkClient)
    
    print('''S->C
    Send salt, B=kv + g**b % N''')
    salt_s2c , B = server.get_salt(), server.get_B()
    client.set_server_id(salt_s2c, B)

    kc = client.get_shared_key()
    ks = server.get_shared_key()

    if rogue_client != None:
        #chal37 when client is rogue
        client.shared_key = rogued_shared_key
    

    print(client.shared_key)
    print(server.shared_key)


    print('''C->S
    Send HMAC-SHA256(K, salt)''')
    csMAC = client.get_Hmac()
    print('''S->C
    Send "OK" if HMAC-SHA256(K, salt) validates''')
    if csMAC == server.get_HMAC():
        print("Passowrd is Verified")
    else:
        print("SRP failed")
    return

def chal36():
    '''Challenge 36 Implement Secure Remote Password'''
    email = 'vlad@yandex.ru'
    passwd = 'abc123'
    secure_remote_passwd(email,passwd)


##############
### Chal37
# break SRP by sending PK = 0

def chal37():
    '''challenge 37, break SRP by sending PK = 0
    this would lead the shared secret to be 1'''
    email = 'vlad@yandex.ru'
    passwd = 'g1'
    N = NIST_P
    g = 2
    k = 3 
    rogue_client = SRPClient(N,g,k,email,passwd)
    # set public key to 0 --> shared secret will be 0
    rogue_client.PK = random.choice([0,N,2*N])
    rogue_client.shared_key = sha256('0').digest()
    secure_remote_passwd(email,passwd, rogue_client, rogue_client.shared_key)


###########
### chal38
# offline dictionary attack on simplified SRP

def simpleSRP_server():
    '''emulating simple SRP server behavior.
    Some values are hard coded into code'''
    N = NIST_P
    g = 2
    email = "Alice@wonderland.net"
    passwd = "cheshire_cat"
    salt = os.urandom(256/8)
    v= modexp(g,int(sha256(salt + passwd).hexdigest(),16)%N, N)
    # I is email address, not used in the code because there is only 
    # one username

    # wait for client's pk
    I,pk_client = yield

    # send salt, B = g**b , u = random number
    secret_key = bin2int(os.urandom(256/8))
    public_key = modexp(g,secret_key,N)
    u = bin2int(os.urandom(128/8))

    proof = yield (salt, public_key, u)
    
    # S = (A * v ** u) ** b
    S = modexp((pk_client * modexp(v,u,N)), secret_key, N)
    K = sha256(str(S)).digest()
    h = hmac.new(K)
    h.update(salt + passwd)
    if proof == h.hexdigest():
        yield True
    yield False


def simpleSRP_client():
    '''emulating simple SRP client behavior'''
    N = NIST_P
    g = 2

    secret_key = bin2int(os.urandom(256/8))
    email = "Alice@wonderland.net"
    passwd = "cheshire_cat"
    public_key = modexp(g,secret_key, N)
    
    (salt, B ,u) = yield email,public_key

    x = int(sha256(salt + passwd).hexdigest(),16)
    S = modexp(B, secret_key + u * x, N)
    K = sha256(str(S)).digest()
    h = hmac.new(K)
    h.update(salt + passwd)
    yield h.hexdigest()


def simpleSRP_orch(server_type):
    '''orchestrates client and server of simple
    SRP'''
    s = server_type()
    c = simpleSRP_client()
    (client_email, client_pk) = c.next()
    s.next()
    (salt, B , u) = s.send((client_email, client_pk))
    proof = c.send((salt,B,u))
    login = s.send(proof)
    if login:
        print("SSPR login successufl")
    else:
        print("SSRP login failed")



def mallorySRP():
    '''Mallory's MITM attack to crack Alice's passwd'''
    # Password dictionary
    passwd_list = ["alice","caterpillar", "cheshire_cat", "jabberwock","mad_hatter",\
                    "queen_of_hearts","white_rabbit"]


    ### Just act like the server
    # but with controlled params
    N = NIST_P
    g = 2
    email = "Alice@wonderland.net"
    #passwd = "wish2know!"
    salt = "YELLOW SUBMARINE"
    #v= modexp(g,int(sha256(salt + passwd).hexdigest(),16)%N, N)
    # I is email address, not used in the code because there is only 
    # one username

    # wait for client's pk
    I,pk_client = yield

    # send salt, B = g**b , u = random number
    secret_key = bin2int(os.urandom(256/8))
    public_key = modexp(g,secret_key,N)
    u = 1

    proof = yield (salt, public_key, u)
    
    # S = (A * v ** u) ** b
    # S = B ** (a + ux)
    # DH -> S = A**b * B **(u*x)
    for passwd in passwd_list:
        x = int(sha256(salt + passwd).hexdigest(),16)
        S = (modexp(pk_client, secret_key, N) * modexp(public_key, u*x, N) ) %N
        K = sha256(str(S)).digest()
        h = hmac.new(K)
        h.update(salt + passwd)
        if proof == h.hexdigest():
            print("Alice's pass is:",passwd)
            yield True
    
    yield False


def chal38():
    # test operation for normal case
    #simpleSRP_orch(simpleSRP_server)
    simpleSRP_orch(mallorySRP)


#############
#### Chal39
# RSA implementaion
def chal39():
    '''implement RSA test out'''
    r1 = rsa.RSA()
    c = r1.encrypt("RSA worked!")
    m = r1.decrypt(c)
    print(m)



#############
#### Chal40
# Implement an E=3 RSA Broadcast attack

def get3ct():
    '''get cipher texts encrypting the same msg from server'''
    m = "YELLOW SUBMARINE"
    r1 = rsa.RSA()
    c1 = r1.encrypt(m)
    print("received a ct")
    r2 = rsa.RSA()
    c2 = r2.encrypt(m)
    print("received a ct")
    r3 = rsa.RSA()
    c3 = r3.encrypt(m)
    print("received a ct")
    return ((c1, r1.getPK()), (c2,r2.getPK()), (c3,r3.getPK()))


def decrypt_broadcast_attack(ctexts):
    t1 = try1(ctexts)
    t2 = try2(ctexts)
    assert t1 == t2
    # now we should take the cube root
    m = cube_root(t1)
    print("msg",m)
    print("decrypted msg is:\n" + str( int2bin(m)))

def cube_root(n):
    '''find n ** 1/3'''
    # m**3 = y --> 3log(m) = log(y)
    error_f = lambda x: x**3 - n
    threshold = 10
    g0 = int(100*(math.log(n,2) / 3))/100.
    g1 = g0 + 0.01
    m0,m1 = int(2**g0), int(2**g1)
    e0,e1 = error_f(m0), error_f(m1)
    assert e0 <= 0
    assert e1 >= 0
    # use binary search to find the answer
    if e0 == 0:
        return m0
    elif e1 == 0:
        return m1
    i = 0
    while e0 < 0 and e1 > 0: 
        i+=1
        m2 = (m0 + m1) // 2
        e2 = error_f(m2)
        if abs(e2) < threshold:
            break
        if e2 == 0:
            return m2
        elif e2 < 0:
            m0 = m2
            e0 = error_f(m0)
        else:
            m1 = m2
            e1 = error_f(m1)
    return (m0 + m1)//2

def try1(ctexts):
    '''my equation to find m**3'''
    ((c1,pk1), (c2,pk2), (c3,pk3)) = ctexts
    n1 = pk1[1]
    n2 = pk2[1]
    n3 = pk3[1]
    
    rh = c1*n2*n3 + c2*n1*n3 + c3*n2*n1
    m3 = rh * invmod(n1*n2 + n2*n3 + n3*n1, n1*n2*n3)
    m3 = m3%(n1*n2*n3)
    return m3


def try2(ctexts):
    '''cryptopals equation based on Chiniese Remainder Theorem'''
    ((c1,pk1), (c2,pk2), (c3,pk3)) = ctexts
    n1 = pk1[1]
    n2 = pk2[1]
    n3 = pk3[1]

    m3 = c1*n2*n3*invmod(n2*n3,n1) + c2*n1*n3*invmod(n1*n3,n2) + c3*n1*n2*invmod(n1*n2,n3)
    m3 = m3%(n1*n2*n3)
    return m3


def chal40():
    '''Implement an E=3 RSA Broadcast attack'''
    ctexts = get3ct()
    decrypt_broadcast_attack(ctexts)

#############
if __name__ == "__main__":
    #chal33()
    #chal34()
    #chal35()
    #chal36()
    #chal37()
    #chal38()
    #chal39()
    chal40()


