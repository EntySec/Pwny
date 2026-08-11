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

import os
import selectors

from hatsploit.lib.ui.jobs import Job

from typing import (
    Union,
    Callable,
    Any,
    Optional
)
from badges import Badges

from pex.string import String
from pex.proto.tlv import (
    TLVPacket,
    TLVClient,
    TLVServerHTTP
)

from pwny.api import *
from pwny.types import *

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)
from Crypto.Cipher import ChaCha20
from cryptography.hazmat.backends import default_backend

MSG_QUEUE_QUIT = b'\xca\xfe\xba\xbe'


class SignalPipe(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended to provide a
    signal pipe to send signals to select call.
    """

    def __init__(self) -> None:
        self.pipe = os.pipe()

        self.read = self.pipe[0]
        self.write = self.pipe[1]

    def sendmsg(self, msg: bytes) -> int:
        """ Send message to pipe.

        :param bytes msg: message (signal) 4-bytes
        :return int: bytes written
        """

        return os.write(self.write, msg)

    def recvmsg(self) -> bytes:
        """ Read message from pipe.

        :return bytes: message (signal) 4-bytes
        """

        return os.read(self.read, 4)


class CipherProcessor(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    implementation of TLV encrypt/decrypt operations.
    """

    def __init__(self) -> None:
        """ Initialize TLV cipher processor.

        :return None: None
        """

        self.key = None
        self.secure = False
        self.algo = None

    def set_key(self, key: bytes, algo: int = ALGO_AES256_CBC) -> None:
        """ Set key for encryption.

        :param str key: key in plain bytes
        :param int algo: cipher algorithm
        :return None: None
        """

        if not key:
            self.secure = False
            return

        self.key = key
        self.algo = algo
        self.secure = True

    def encrypt(self, packet: TLVPacket) -> bytes:
        """ Encrypt TLV packet with cipher.

        :param TLVPacket packet: TLV packet to encrypt
        :return bytes: encrypted TLV packet data
        """

        if not self.key:
            raise RuntimeError("No key set, unable to encrypt!")

        data = packet.buffer

        if self.algo == ALGO_AES256_CBC:
            iv = os.urandom(16)

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend)
            encryptor = cipher.encryptor()

            padded_data = data + (16 - len(data) % 16) * bytes([16 - len(data) % 16])
            return iv + encryptor.update(padded_data) + encryptor.finalize()

        if self.algo == ALGO_CHACHA20:
            iv = os.urandom(12)

            cipher = ChaCha20.new(key=self.key, nonce=iv)
            return iv + cipher.encrypt(data)

        return data

    def decrypt(self, data: bytes) -> TLVPacket:
        if not self.key:
            raise RuntimeError("No key set, unable to decrypt!")

        if self.algo == ALGO_AES256_CBC:
            iv = data[:16]
            data = data[16:]

            cipher = Cipher(algorithms.AES(self.key),
                            modes.CBC(iv),
                            backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(data) + decryptor.finalize()

            # --- Remove PKCS#7 padding ---
            if not padded_data:
                raise ValueError("Decrypted data is empty")

            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16 or pad_len > len(padded_data):
                raise ValueError(f"Invalid PKCS#7 padding length: {pad_len}")

            if padded_data[-pad_len:] != bytes([pad_len]) * pad_len:
                raise ValueError("Invalid PKCS#7 padding bytes")

            unpadded = padded_data[:-pad_len]
            return TLVPacket(unpadded)

        if self.algo == ALGO_CHACHA20:
            iv = data[:12]
            data = data[12:]
            cipher = ChaCha20.new(key=self.key, nonce=iv)
            return TLVPacket(cipher.decrypt(data))

        return TLVPacket(data)


class QueueProcessor(Badges):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    implementation of TLV queue processor.
    """

    def __init__(self) -> None:
        """ Initialize TLV queue processor.

        :return None: None
        """

        self.queue = []
        self.events = {}

        self.verbose = False

    def verbose_print(self, *args, **kwargs) -> None:
        """ Print something if verbose printing is enabled.

        :return None: None
        """

        if self.verbose:
            self.print_information(*args, **kwargs)

    def create_event(self, target: Union[Callable[..., Any], TLVPacket], query: dict,
                     event: Optional[int] = None, args: list = [],
                     noapi: bool = True, ttl: Optional[int] = None) -> int:
        """ Create event on a pipe (wait for event).

        :param Union[Callable[..., Any], TLVPacket] target: function to execute on event or packet
        template
        :param dict query: event query
        :param Optional[int] event: type of data you expect to receive
        :param list args: function args
        :param bool noapi: packet should not include API call tag
        :param Optional[int] ttl: time to live for event
        :return int: assigned event ID
        """

        event_id = 0
        while event_id in self.events or \
                event_id < len(self.events):
            event_id += 1

        self.events[event_id] = {
            'Target': target,
            'Query': query,
            'Args': args,
            'Event': event,
            'NoTag': noapi,
            'TTL': ttl,
        }

        self.verbose_print(f"Event created with ID ({str(event_id)})")
        self.verbose_print(f"Re-running queue events for event {str(event_id)}")

        for packet in self.queue:
            self.queue_run_events(packet)

        return event_id

    def queue_run_events(self, packet: TLVPacket) -> bool:
        """ Execute events and check if packet can be
        used for a callback.

        :param TLVPacket packet: TLV packet to check
        :return bool: True if event executed with success else False
        """

        for event_id, event in self.events.copy().items():
            if event['NoTag'] and packet.get_int(TLV_TYPE_TAG, delete=False):
                continue

            if event['Event'] and not packet.get_raw(event['Event'], delete=False):
                continue

            if not self.tlv_query(packet, event['Query']):
                continue

            if event['TTL'] is not None:
                if event['TTL']:
                    event['TTL'] -= 1

                if not event['TTL']:
                    self.events.pop(event_id)

            self.verbose_print(f"Event with ID {str(event_id)} fired ({str(len(packet.buffer))} bytes)")

            if isinstance(event['Target'], TLVPacket):
                event['Target'].__init__(packet.buffer)
            else:
                event['Target'](packet, *event['Args'])

            return True
        return False

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
            if not self.tlv_query(packet, args):
                continue

            if delete:
                self.queue.remove(packet)

            return packet


class TLV(QueueProcessor):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    TLV negotiation methods.
    """

    def __init__(self, client: Union[TLVClient, tuple], die: bool = True,
                 verbose: bool = False) -> None:
        """ Initialize TLV.

        :param Union[TLVClient, tuple] client: TLV client
        :param bool die: raise errors if status is wrong
        :param bool verbose: verbose dump packet for inspection
        :return None: None
        """

        super().__init__()

        if isinstance(client, TLVClient):
            self.ingress = client
            self.egress = client

        else:
            self.ingress = client[1]
            self.egress = client[0]

        self.job = None
        self.client = client

        self.running = False
        self.error = None

        self.die = die
        self.verbose = verbose

        self.signal = SignalPipe()
        self.cipher = CipherProcessor()

    def queue_interrupt(self) -> None:
        """ Interrupt queue thread.

        :return None: None
        """

        if not self.running:
            return

        self.verbose_print("Interrupting TLV queue thread")
        self.signal.sendmsg(MSG_QUEUE_QUIT)
        self.job.join()

    def queue_resume(self) -> None:
        """ Resume queue thread.

        :return None: None
        """

        if self.running:
            return

        self.verbose_print("Resumed TLV queue thread")
        self.job = Job(target=self.queue_job)
        self.job.start()

    def queue_job(self) -> None:
        """ Read TLVPacket's in queue in thread.

        :param bool error: raise errors if status is wrong
        :param bool verbose: verbose dump packet for inspection
        :return None: None
        """

        self.running = True
        selector = selectors.SelectSelector()

        selector.register(self.ingress.client, selectors.EVENT_READ)
        selector.register(self.signal.read, selectors.EVENT_READ)

        while self.running:
            for key, events in selector.select():
                if key.fileobj is self.signal.read:
                    if self.signal.recvmsg() == MSG_QUEUE_QUIT:
                        self.verbose_print("TLV queue thread received quit signal")
                        self.running = False

                        return

                elif key.fileobj is self.ingress.client:
                    try:
                        packet = self.read()

                    except Exception as e:
                        self.running = False
                        self.error = str(e)

                        continue

                    if not packet:
                        continue

                    if not self.queue_run_events(packet):
                        self.queue.append(packet)

    def read(self, block: bool = True) -> Union[TLVPacket, None]:
        """ Read TLV packet.

        :param bool block: True to block socket else False
        :return Union[TLVPacket, None]: TLV packet or None if None received
        """

        tlv = self.ingress.read(block=block)

        if not tlv:
            return

        self.verbose_print(f"Decapsulating received TLV packet ({str(len(tlv.buffer))} bytes)")
        group = tlv.get_raw(TLV_TYPE_GROUP)

        if self.cipher.secure:
            self.verbose_print(f"Decrypting decapsulated TLV packet ({str(len(group))} bytes)")
            group = self.cipher.decrypt(group)
        else:
            group = TLVPacket(group)

        if self.verbose:
            self.print_information(f"Read TLV packet ({str(len(group.buffer))} bytes, "
                                   f"{str(len(group))} objects)")
            length = 0

            for line in String().hexdump(group.buffer):
                self.print_information(line)
                length = len(line)

            self.print_empty('-' * (length + 4))

        if self.die:
            status = group.get_int(TLV_TYPE_STATUS, delete=False)

            if status == TLV_STATUS_NOT_IMPLEMENTED:
                self.print_error("Feature is not implemented yet!")

        return group

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        tlv = TLVPacket()

        if self.cipher.secure:
            self.verbose_print(f"Encrypting and encapsulating TLV packet ({str(len(packet.buffer))} bytes)")
            tlv.add_raw(TLV_TYPE_GROUP, self.cipher.encrypt(packet))
        else:
            self.verbose_print(f"Encapsulating TLV packet ({str(len(packet.buffer))} bytes)")
            tlv.add_tlv(TLV_TYPE_GROUP, packet)

        if self.verbose:
            self.print_information(f"Sent TLV packet ({str(len(packet.buffer))} bytes, "
                                   f"{str(len(packet))} objects)")
            length = 0

            for line in String().hexdump(packet.buffer):
                self.print_information(line)
                length = len(line)

            self.print_empty('-' * (length + 4))
        self.egress.send(tlv)

    def close(self) -> None:
        """ Close TLV channel.

        :return None: None
        """

        self.ingress.close()
        self.egress.close()


class HTTPTLV(QueueProcessor):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    TLV negotiation methods (for HTTP).
    """

    def __init__(self, server: TLVServerHTTP, die: bool = True,
                 verbose: bool = False) -> None:
        """ Initialize TLV for HTTP.

        :param TLVServerHTTP client: TLV HTTP server
        :param bool die: raise errors if status is wrong
        :param bool verbose: verbose dump packet for inspection
        :return None: None
        """

        super().__init__()

        self.server = server

        self.running = True
        self.error = None
        self.die = die
        self.verbose = verbose

        self.cipher = CipherProcessor()

    def redirect(self, urlpath: str) -> None:
        """ Set new URI and redirect client to it.

        :param str urlpath: new URL path
        :return None: None
        """

        self.server.set_urlpath(urlpath)

    def queue_stop(self) -> None:
        """ Stop queue thread.

        :return None: None
        """

        self.server.close()

    def queue_start(self) -> None:
        """ Start queue thread.

        :return None: None
        """

        self.server.callback = self.queue_callback

    def queue_callback(self, packet: TLVPacket) -> None:
        """ Queue callback that is triggered when server
        receives TLV packet.

        :param TLVPacket packet: received TLV packet
        :return None: None
        """

        if not packet:
            return

        group = packet.get_raw(TLV_TYPE_GROUP)

        while group:
            self.verbose_print(f"Decapsulating received TLV packet ({str(len(packet.buffer))} bytes)")

            if self.cipher.secure:
                self.verbose_print(f"Decrypting decapsulated TLV packet ({str(len(group))} bytes)")
                group = self.cipher.decrypt(group)
            else:
                group = TLVPacket(group)

            if self.verbose:
                self.print_information(f"Read TLV packet ({str(len(group.buffer))} bytes, "
                                       f"{str(len(group))} objects)")
                length = 0
                for line in String().hexdump(group.buffer):
                    self.print_information(line)
                    length = len(line)

                self.print_empty('-' * (length + 4))

            if self.die:
                status = group.get_int(TLV_TYPE_STATUS, delete=False)

                if status == TLV_STATUS_NOT_IMPLEMENTED:
                    self.print_error("Feature is not implemented yet!")

            if not self.queue_run_events(group):
                self.queue.append(group)

            group = packet.get_raw(TLV_TYPE_GROUP)

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        tlv = TLVPacket()

        if self.cipher.secure:
            self.verbose_print(f"Encrypting and encapsulating TLV packet ({str(len(packet.buffer))} bytes)")
            tlv.add_raw(TLV_TYPE_GROUP, self.cipher.encrypt(packet))

        else:
            self.verbose_print(f"Encapsulating TLV packet ({str(len(packet.buffer))} bytes)")
            tlv.add_tlv(TLV_TYPE_GROUP, packet)

        if self.verbose:
            self.print_information(f"Sent TLV packet ({str(len(packet.buffer))} bytes, "
                                   f"{str(len(packet))} objects)")
            length = 0

            for line in String().hexdump(packet.buffer):
                self.print_information(line)
                length = len(line)

            self.print_empty('-' * (length + 4))
        self.server.send(tlv)
