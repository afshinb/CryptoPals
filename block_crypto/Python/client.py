#!/usr/bin/python           # This is client.py file

import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = 'localhost'
port = 9600

s.connect((host, port))
print s.recv(1024)
s.sendall("Hello")
print s.recv(1024)

s.close()

