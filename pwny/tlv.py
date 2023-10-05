"""
MIT License

Copyright (c) 2020-2023 EntySec

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

from .types import *

from pex.proto.tlv import TLVPacket, TLVClient


class TLV(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    TLV negotiation methods.
    """

    def __init__(self, client: TLVClient) -> None:
        """ Initialize TLV.

        :param TLVClient client: TLV client
        :return None: None
        """

        self.client = client

    def read(self) -> TLVPacket:
        """ Read TLV packet.

        :return TLVPacket: TLV packet
        """

        tlv = self.client.read()
        count = tlv.get_int(TLV_TYPE_COUNT)

        if count:
            while count > 0:
                tlv += self.client.read()
                count -= 1

        return tlv

    def write(self, packet: TLVPacket) -> None:
        """ Write TLV packet.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        tlv = TLVPacket()
        tlv.add_int(TLV_TYPE_COUNT, len(packet))
        tlv += packet

        self.client.send(tlv)
