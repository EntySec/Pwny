import sys
import socket
import time

from pex.arch import *
from pex.platform import *

from pwny.session import PwnySession


def main():
    s = socket.socket()
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen()

    print('Waiting for connection (egress) ...')
    c1, a = s.accept()
    print('Waiting for connection (ingress) ...')
    c2, a = s.accept()

    p = PwnySession()
    p.info['Platform'] = sys.argv[3]
    p.info['Arch'] = sys.argv[4]
    p.open((c1, c2))
    p.interact()


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(f'Usage: {sys.argv[0]} <host> <port> <platform> <arch>')
        sys.exit(1)

    main()
    sys.exit(0)
