import socket
from pwny.session import PwnySession

s = socket.socket()
s.bind(('192.168.64.1', 8888))
s.listen()
c, a = s.accept()

print(a)

p = PwnySession()
p.details['Platform'] = 'linux'
p.details['Arch'] = 'aarch64'
p.open(c)
p.interact()
