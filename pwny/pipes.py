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

from typing import Optional

from pwny.api import *

from hatsploit.lib.session import Session


class Pipes(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    pipes client.
    """

    def __init__(self, session: Session) -> None:
        """ Initialize pipes client.

        :param Session session: session
        :return None: None
        """

        self.session = session

        self.pipes = {}
        self.plugin_pipes = {}

    def check_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> None:
        """ Check if pipe exists.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        pipes = self.pipes

        if plugin is not None:
            if plugin not in self.plugin_pipes:
                raise RuntimeError(f"Plugin has no pipe with ID #{str(pipe_id)}!")

            pipes = self.plugin_pipes[plugin]

        if pipe_type not in pipes:
            raise RuntimeError(f"Pipe {str(pipe_id)} type and ID mismatch!")

        if pipe_id not in pipes[pipe_type]:
            raise RuntimeError(f"No such pipe with ID {str(pipe_id)}!")

    def heartbeat_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> bool:
        """ Check pipe is alive or not.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return bool: True if alive else False
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_HEARTBEAT,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            return False

        return True

    def tell_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> int:
        """ Tell from pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return int: offset
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_TELL,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to tell from pipe {str(pipe_id)}!")

        return tlv.get_int(PIPE_TYPE_OFFSET)

    def seek_pipe(self, pipe_type: int, pipe_id: int,
                  offset: int, whence: int, plugin: Optional[int] = None) -> None:
        """ Seek in the pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int offset: offset
        :param int whence: whence
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_SEEK,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_OFFSET: offset,
                PIPE_TYPE_WHENCE: whence,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to seek in pipe {str(pipe_id)}!")

    def write_pipe(self, pipe_type: int, pipe_id: int, buffer: bytes,
                   plugin: Optional[int] = None) -> None:
        """ Write stream to pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param bytes buffer: buffer to write
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_WRITE,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_LENGTH: len(buffer),
                PIPE_TYPE_BUFFER: buffer,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to write to pipe {str(pipe_id)}!")

    def read_pipe(self, pipe_type: int, pipe_id: int, size: int,
                  plugin: Optional[int] = None) -> bytes:
        """ Read stream from pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int size: count of bytes to read
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return bytes: bytes
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_READ,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_LENGTH: size,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to read from pipe {str(pipe_id)}!")

        return tlv.get_raw(PIPE_TYPE_BUFFER)

    def create_pipe(self, pipe_type: int, args: dict = {},
                    plugin: Optional[int] = None) -> int:
        """ Create new pipe of type.

        :param int pipe_type: type of pipe
        :param dict args: additional args
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return int: pipe ID
        :raises RuntimeError: with trailing error message
        """

        pipes = self.pipes

        if plugin is not None:
            if plugin not in self.plugin_pipes:
                self.plugin_pipes[plugin] = {}

            pipes = self.plugin_pipes[plugin]

        if pipe_type not in pipes:
            pipes[pipe_type] = []

        pipe_id = len(pipes[pipe_type])

        args.update({
            PIPE_TYPE_TYPE: pipe_type,
            PIPE_TYPE_ID: pipe_id
        })

        tlv = self.session.send_command(
            tag=PIPE_CREATE,
            args=args
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to create pipe {str(pipe_id)}!")

        pipes[pipe_type].append(pipe_id)
        return pipe_id

    def destroy_pipe(self, pipe_type: int, pipe_id: int, args: dict = {},
                     plugin: Optional[int] = None) -> None:
        """ Destroy pipe of type by ID.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param dict args: additional args
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        args.update({
            PIPE_TYPE_TYPE: pipe_type,
            PIPE_TYPE_ID: pipe_id
        })

        tlv = self.session.send_command(
            tag=PIPE_DESTROY,
            args=args
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to destroy pipe {str(pipe_id)}!")

        pipes = self.pipes

        if plugin is not None:
            pipes = self.plugin_pipes[plugin]

        pipes[pipe_type].remove(pipe_id)
