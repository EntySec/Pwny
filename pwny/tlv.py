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

import os
import threading

from typing import Union
from badges import Badges

from pex.string import String
from pex.proto.tlv import TLVPacket, TLVClient

from pwny.api import *
from pwny.types import *

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)
from cryptography.hazmat.backends import default_backend


class TLV(Badges, String):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    TLV negotiation methods.
    """

    def __init__(self, client: TLVClient, args: list = []) -> None:
        """ Initialize TLV.

        :param TLVClient client: TLV client
        :param list args: arguments
        :return None: None
        """

        self.client = client
        self.key = None
        self.secure = False

        self.queue = []
        self.events = {}
        self.thread = None

        self.running = False
        self.stopped = True

        self.args = args

    def queue_interrupt(self) -> None:
        """ Interrupt queue thread.

        :return None: None
        """

        self.running = False

        while not self.stopped:
            continue

    def queue_resume(self) -> None:
        """ Resume queue thread.

        :return None: None
        """

        if self.running:
            return

        self.thread = threading.Thread(
            target=self.queue_thread, args=self.args)
        self.thread.setDaemon(True)

        self.running = True
        self.stopped = False

        self.thread.start()

    def queue_thread(self, error: bool = True, verbose: bool = False) -> None:
        """ Read TLVPacket's in queue in thread.

        :param bool error: raise errors if status is wrong
        :param bool verbose: verbose dump packet for inspection
        :return None: None
        """

        while self.running:
            try:
                packet = self.read(
                    block=False,
                    error=error,
                    verbose=verbose
                )

                if not packet:
                    continue

                self.queue.append(packet)

                if packet.get_int(TLV_TYPE_TAG, delete=False):
                    continue

                for event_id, event in self.events.items():
                    if not self.tlv_query(packet, event['Query']):
                        continue

                    if not packet.get_raw(event['Event'], delete=False):
                        continue

                    event['Target'](packet, *event['Args'])

                    self.queue.remove(packet)
                    break

            except Exception:
                break

        self.stopped = True

    def queue_delete(self, packet: TLVPacket) -> None:
        """ Delete packet from queue.

        :param TLVPacket packet: TLV packet to delete
        :return None: None
        """

        if packet in self.queue:
            self.queue.remove(packet)

    @staticmethod
    def tlv_query(packet: TLVPacket, args: dict) -> bool:
        """ Check if TLVPacket has specific entries.

        :param TLVPacket packet: TLV packet
        :param dict args: query args to scan
        :return bool: True if exists else False
        """

        found = 0

        for type, value in args.items():
            if isinstance(value, str):
                if packet.get_string(type, delete=False) == value:
                    found += 1

            elif isinstance(value, int):
                if packet.get_int(type, delete=False) == value:
                    found += 1

            elif isinstance(value, TLVPacket):
                if packet.get_tlv(type, delete=False) == value:
                    found += 1

            else:
                if packet.get_raw(type, delete=False) == value:
                    found += 1

        if found == len(args):
            return True

        return False

    def queue_find(self, args: dict, delete: bool = True) -> Union[TLVPacket, None]:
        """ Find first TLVPacket with following args.

        :param dict args: dictionary of args
        :param bool delete: delete from queue if found
        :return Union[TLVPacket, None]: first TLVPacket found or None
        """

        for packet in self.queue:
            if self.tlv_query(packet, args):
                if delete:
                    self.queue.remove(packet)

                return packet

    def encrypt(self, packet: TLVPacket) -> bytes:
        """ Encrypt TLV packet with AES CBC 256-bit.

        :param TLVPacket packet: TLV packet to encrypt
        :return bytes: encrypted TLV packet data
        """

        if not self.key:
            raise RuntimeError("No AES key set, unable to encrypt!")

        iv = os.urandom(16)
        data = packet.buffer

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend)
        encryptor = cipher.encryptor()

        padded_data = data + (16 - len(data) % 16) * bytes([16 - len(data) % 16])
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data: bytes) -> TLVPacket:
        """ Decrypt TLV packet with AES CBC 256-bit.

        :param bytes data: data to decrypt
        :return TLVPacket: decrypted TLV packet
        """

        iv = data[:16]
        data = data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend)
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(data) + decryptor.finalize()
        return TLVPacket(padded_data)

    def read(self, error: bool = False, verbose: bool = False,
             block: bool = True) -> Union[TLVPacket, None]:
        """ Read TLV packet.

        :param bool error: raise errors if status is wrong
        :param bool verbose: verbose dump packet for inspection
        :param bool block: True to block socket else False
        :return Union[TLVPacket, None]: TLV packet or None if None received
        """

        tlv = self.client.read(block=block)

        if not tlv:
            return

        group = tlv.get_raw(TLV_TYPE_GROUP)

        if self.secure:
            group = self.decrypt(group)
        else:
            group = TLVPacket(group)

        if verbose:
            self.print_information(f"Read TLV packet ({str(len(group.buffer))} bytes, "
                                   f"{str(len(group))} objects)")
            for line in self.hexdump(group.buffer):
                self.print_information(line)

        if error:
            status = group.get_int(TLV_TYPE_STATUS, delete=False)

            if status == TLV_STATUS_NOT_IMPLEMENTED:
                self.print_error("Feature is not implemented yet!")

        return group

    def send(self, packet: TLVPacket, verbose: bool = False) -> None:
        """ Send TLV packet.

        :param TLVPacket packet: TLV packet
        :param bool verbose: verbose dump packet for inspection
        :return None: None
        """

        tlv = TLVPacket()

        if self.secure:
            tlv.add_raw(TLV_TYPE_GROUP, self.encrypt(packet))
        else:
            tlv.add_tlv(TLV_TYPE_GROUP, packet)

        if verbose:
            self.print_information(f"Sent TLV packet ({str(len(packet.buffer))} bytes, "
                                   f"{str(len(packet))} objects)")
            for line in self.hexdump(packet.buffer):
                self.print_information(line)

        self.client.send(tlv)
