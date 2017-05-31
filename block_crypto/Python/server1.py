'''non blocking server using
async'''

import socket, time, select
from collections import namedtuple
from chal4 import verify_mac, insecure_compare


Session = namedtuple('Session', ['address','file'])

sessions = dict()       # {csocket : Session(address, file)}
callback = dict()       # {csocket : callback(client, line)



def reactor(host = 'localhost', port=9600):
    'Main event loop that triggers the appropriate bussines logic callbacks'
    s = socket.socket()
    s.bind((host,port))
    s.listen(5)
    s.setblocking(0)
    print("Server is up and running")
    try:
        while True:
            try:
                c,a = s.accept()
            except socket.error:
                pass
            else:
                connect(c,a)

            # serving clients that have data

            ready_to_read , _ , _ = select.select(sessions, [], [], 0.1)
            for c in ready_to_read:
                line = sessions[c].file.readline()
                if line:
                    callback[c](c, line.rstrip())
                else:
                    disconnect(c)

            time.sleep(0.1)
    finally:
        s.close()


def connect(c,a):
    'reactor logic for new connection'
    sessions[c] = Session(a, c.makefile())
    on_connect(c)


def disconnect(c):
    'reactor logic to end session'
    on_disconnect(c)
    sessions[c].file.close()
    c.close()
    sessions.pop(c,None)
    callback.pop(c,None)

def on_connect(c):
    pass

def on_disconnect(c):
    pass


############## End Of server logic #########


def on_connect(c):
    print("recevied connection from", sessions[c].address)
    c.sendall("connected to server")
    callback[c] = verify_mac


def on_disconnect(c):
    print(sessions[c].address, 'quit')

def verify_mac2(c,line):
    if line == 'quit':
        disconnect(c)
    c.sendall("Hello hello how low?")

if __name__ == "__main__":
    reactor('localhost',9602)





