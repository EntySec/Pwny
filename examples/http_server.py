import sys
import threading

from pex.proto.http import HTTPListener

from pex.arch import *
from pex.platform import *

from pwny.session import PwnyHTTPSession


def main():
    print('Waiting for connection ...')
    l = HTTPListener(sys.argv[1], sys.argv[2])
    l.listen()

    thread = threading.Thread(target=l.loop)
    thread.start()

    p = PwnyHTTPSession()
    p.info['Platform'] = sys.argv[3]
    p.info['Arch'] = sys.argv[4]
    p.open(l)
    p.interact()

    l.stop()
    thread.join()


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(f'Usage: {sys.argv[0]} <host> <port> <platform> <arch>')
        sys.exit(1)

    main()
    sys.exit(0)
