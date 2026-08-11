"""
MIT License

Copyright (c) 2020-2026 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import ssl
import base64
import hashlib
import tempfile

from OpenSSL import crypto
from pex.proto.http import HTTPListener


def generate_self_signed(keyfile: str, certfile: str) -> None:
    """ Generate a self-signed RSA-2048 certificate.

    :param str keyfile: path to write PEM-encoded private key
    :param str certfile: path to write PEM-encoded certificate
    :return None: None
    """

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_serial_number(0)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(keyfile, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(certfile, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def extract_pin(certfile: str) -> str:
    """ Extract the SPKI SHA-256 pin from a PEM certificate.

    Returns the pin in curl's format: sha256//base64hash

    :param str certfile: path to PEM certificate
    :return str: pin string (e.g. sha256//abc123...)
    """

    with open(certfile, 'rb') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    spki_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    digest = hashlib.sha256(spki_der).digest()
    pin = base64.b64encode(digest).decode()

    return f"sha256//{pin}"


class HTTPSListener(HTTPListener):
    """ HTTPS listener with self-signed certificate and TLS pin extraction.

    Extends pex HTTPListener by wrapping the server socket with TLS
    after binding. The SPKI SHA-256 pin can be retrieved via the
    pin property to embed in implant URIs.
    """

    def __init__(self, host: str, port: int, keyfile: str = '',
                 certfile: str = '') -> None:
        self._keyfile = keyfile
        self._certfile = certfile
        self._pin = None

        super().__init__(host, port)

    def listen(self) -> None:
        """ Start the HTTPS listener.

        Generates a self-signed cert if needed, wraps the server
        socket with TLS, and extracts the SPKI pin.

        :return None: None
        """

        super().listen()

        if not self._keyfile or not self._certfile:
            self._tmpdir = tempfile.mkdtemp(prefix='pwny_')
            self._keyfile = self._keyfile or f'{self._tmpdir}/server.key'
            self._certfile = self._certfile or f'{self._tmpdir}/server.crt'
            generate_self_signed(self._keyfile, self._certfile)
        
        self._pin = extract_pin(self._certfile)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile)
        self.sock.socket = ctx.wrap_socket(self.sock.socket, server_side=True)

    @property
    def pin(self) -> str:
        """ Get the SPKI SHA-256 pin for this listener's certificate.

        :return str: pin in curl format (sha256//base64hash)
        """

        if self._pin is None:
            raise RuntimeError("Listener not started yet")
        return self._pin
