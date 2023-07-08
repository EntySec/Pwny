import socket

from pwny.session import PwnySession

s = socket.socket()
s.bind(('127.0.0.1', 8888))
s.listen()
c, a = s.accept()

print(f'Connected {a[0]}')

session = PwnySession()

session.details['Platform'] = 'linux'
session.details['Architecture'] = 'x64'

session.open(c)
session.interact()
