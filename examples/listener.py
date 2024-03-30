import sys
import socket

from pex.arch.types import *
from pex.platform.types import *

from pwny.session import PwnySession


def main():
    s = socket.socket()
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen()

    print('Waiting for connection ...', end=' ')
    c, a = s.accept()
    print(f'Connection from {a[0]}:{str(a[1])}\n')

    p = PwnySession()
    p.details['Platform'] = OS_LINUX
    p.details['Arch'] = ARCH_AARCH64
    p.open(c, loader=False)
    p.set_prompt('%red%bold$ %end')
    p.interact()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <host> <port>')
        sys.exit(1)

    main()
    sys.exit(0)
