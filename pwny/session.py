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

from typing import Union, Optional

from pwny import Pwny

from pwny.types import *
from pwny.api import *

from pwny.tlv import TLV
from pwny.files import Files
from pwny.console import Console

from hatsploit.lib.loot import Loot
from hatsploit.lib.session import Session

from pex.proto.tlv import TLVClient, TLVPacket


class PwnySession(Pwny, Session, Console):
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
        self.terminated = False

        self.files = Files(self)

        self.details.update({
            'Type': "pwny"
        })

    def open(self, client: socket.socket) -> None:
        """ Open the Pwny session.

        :param socket.socket client: client to open session with
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        """
        client.send(self.get_implant(
             platform=self.details['Platform'],
             arch=self.details['Arch']
        ))
        """

        self.channel = TLV(
            TLVClient(client))
        tlv = self.channel.read()

        self.uuid = tlv.get_string(TLV_TYPE_UUID)

        if self.uuid:
            self.start_pwny(self)
            return

        raise RuntimeError("No UUID received or UUID broken!")

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.channel.close()

    def heartbeat(self) -> bool:
        """ Check the Pwny session heartbeat.

        :return bool: True if the Pwny session is alive
        """

        return not self.terminated

    def send_command(self, tag: int, args: dict = {}, plugin: Optional[int] = None) -> TLVPacket:
        """ Send command to the Pwny session.

        :param int tag: tag
        :param dict args: command arguments with their types
        :param Optional[int] plugin: plugin ID if tag is presented within the plugin
        :return TLVPacket: packets
        """

        tlv = TLVPacket()

        if plugin is not None:
            tlv.add_int(TLV_TYPE_TAB_ID, plugin)

        tlv.add_int(TLV_TYPE_TAG, tag)
        tlv.add_from_dict(args)

        self.channel.send(tlv)
        return self.channel.read()

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        return self.files.read_file(remote_file, local_path)

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        return self.files.send_file(local_file, remote_path)

    def interact(self) -> None:
        """ Interact with the Pwny session.

        :return None: None
        """

        self.pwny_console()
