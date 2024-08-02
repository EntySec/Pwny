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

import sys
import getch
import ctypes
import threading
import selectors

from pwny.api import *
from pwny.types import *

from pex.string import String
from pex.proto.tlv import TLVPacket

from hatsploit.lib.core.session import Session

from typing import Union
from badges import Badges

FLAG_FORK = 0 << 0
FLAG_NO_FORK = 1 << 0
FLAG_FAKE_PTY = 1 << 1


class Spawn(Badges, String):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    spawner for binaries.
    """

    def __init__(self, session: Session) -> None:
        """ Initialize spawn client.

        :param Session session: session
        :return None: None
        """

        self.session = session
        self.pipes = session.pipes

        self.closed = False

    @staticmethod
    def read_event(packet: TLVPacket) -> None:
        """ Read output from pipe.

        :param TLVPacket packet: packet received from pipe
        :return None: None
        """

        buffer = packet.get_raw(PIPE_TYPE_BUFFER)

        sys.stdout.write(buffer.decode(errors='ignore'))
        sys.stdout.flush()

    def heartbeat_event(self, packet: TLVPacket) -> None:
        """ Check pipe heartbeat.

        :param TLVPacket packet: packet received from pipe
        :return None: None
        """

        if packet.get_int(PIPE_TYPE_HEARTBEAT) != TLV_STATUS_SUCCESS:
            self.closed = True

    def write_thread(self, pipe_id: int) -> None:
        """ Thread for writing.

        :param int pipe_id: pipe ID
        :return None: None
        """

        selector = selectors.SelectSelector()
        selector.register(sys.stdin, selectors.EVENT_READ)

        while not self.closed:
            for key, events in selector.select():
                if key.fileobj is not sys.stdin:
                    continue

                try:
                    line = sys.stdin.readline()

                    if not line:
                        pass

                    self.pipes.write_pipe(PROCESS_PIPE, pipe_id, (line + '\n').encode())
                except EOFError:
                    pass

    def change_dir(self, path: str) -> None:
        """ Change directory.

        :param str path: path to change
        :return None: None
        """

        result = self.session.send_command(
            tag=FS_CHDIR,
            args={
                TLV_TYPE_PATH: path
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote directory: {path}: does not exist!")

    def is_dir(self, path: str) -> bool:
        """ Check if remote path is directory or not.

        :param str path: remote path
        :return bool: True if directory else False
        """

        result = self.session.send_command(
            tag=FS_STAT,
            args={
                TLV_TYPE_PATH: path
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            return False

        buffer = result.get_raw(TLV_TYPE_BYTES)
        hash = self.bytes_to_stat(buffer)

        if self.mode_type(hash.get('st_mode', 0)) == 'directory':
            return True

        return False

    def search_path(self, path: str, name: str) -> Union[str, None]:
        """ Search binary if path by name.

        :param str path: path to search for binary in
        :param str name: binary name to search for
        :return Union[str, None]: full path if found else None
        """

        result = self.session.send_command(
            tag=FS_LIST,
            args={
                TLV_TYPE_PATH: path
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            return

        stat = result.get_tlv(TLV_TYPE_GROUP)

        while stat:
            if stat.get_string(TLV_TYPE_FILENAME) == name:
                return stat.get_string(TLV_TYPE_PATH)

            stat = result.get_tlv(TLV_TYPE_GROUP)

    def spawn(self, path: str, args: list = []) -> bool:
        """ Execute path.

        :param str path: path to execute
        :param list args: command-line arguments
        :return bool: True if success else False
        """

        if self.is_dir(path):
            self.change_dir(path)
            return True

        try:
            pipe_id = self.pipes.create_pipe(
                pipe_type=PROCESS_PIPE,
                args={
                    TLV_TYPE_INT: FLAG_NO_FORK,
                    TLV_TYPE_FILENAME: path,
                    PROCESS_TYPE_PROCESS_ARGV: ' '.join(args)
                },
                flags=PIPE_INTERACTIVE
            )

        except RuntimeError:
            self.print_error(f"Failed to spawn process for {path}!")
            return False

        self.pipes.create_event(
            pipe_type=PROCESS_PIPE,
            pipe_id=pipe_id,
            pipe_data=PIPE_TYPE_BUFFER,
            target=self.read_event
        )

        self.pipes.create_event(
            pipe_type=PROCESS_PIPE,
            pipe_id=pipe_id,
            pipe_data=PIPE_TYPE_HEARTBEAT,
            target=self.heartbeat_event
        )

        write_thread = threading.Thread(target=self.write_thread, args=(pipe_id,))
        write_thread.setDaemon(True)
        write_thread.start()

        try:
            while not self.closed:
                pass
        except KeyboardInterrupt:
            self.print_process("Cleaning up...")
            self.closed = True

        if write_thread.is_alive():
            exc = ctypes.py_object(SystemExit)
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(write_thread.ident), exc)

            if res > 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(write_thread.ident, None)

        self.pipes.destroy_pipe(PROCESS_PIPE, pipe_id)
        return True
