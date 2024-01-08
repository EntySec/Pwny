"""
MIT License

Copyright (c) 2020-2024 EntySec

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

from pwny.types import *

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

    def read(self, error: bool = False) -> TLVPacket:
        """ Read TLV packet.

        :param bool error: raise errors if status is wrong
        :return TLVPacket: TLV packet
        :raises RuntimeError: with trailing error message
        """

        tlv = self.client.read()
        group = tlv.get_tlv(TLV_TYPE_GROUP)

        if error:
            status = group.get_int(TLV_TYPE_STATUS, delete=False)

            if status == TLV_STATUS_NOT_IMPLEMENTED:
                raise RuntimeError("Feature is not implemented yet!")

        return group

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        tlv = TLVPacket()
        tlv.add_tlv(TLV_TYPE_GROUP, packet)

        self.client.send(tlv)
