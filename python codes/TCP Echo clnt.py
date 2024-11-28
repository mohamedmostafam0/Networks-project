""" 
A simple echo client 
""" 

import socket 

host = 'localhost' 
port = 10000 
size = 1024 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect((host,port))
data = s.recv(size)
if len(data):
 print('Received:', data.decode('utf-8'))
data="message goes here"
while len(data):
   messgae= input('Input lowercase sentence (type quit to end communication":')
   s.send(messgae.encode('utf-8')) 
   data = s.recv(size) 
   print ('Received:', data.decode('utf-8'))
   if messgae=="quit":
    data=''			
s.close() 