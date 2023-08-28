import socket
from pwny.session import PwnySession

s = socket.socket()
s.bind(('127.0.0.1', 8888))
s.listen()
c, a = s.accept()

print(a)

p = PwnySession()
p.open(c)
p.interact()
