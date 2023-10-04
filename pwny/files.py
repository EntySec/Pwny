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

from typing import Any

from .__main__ import Pwny

from .types import *
from .api import *

from badges import Badges


class Files(Pwny, Badges):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing a
    tools for sending and reading files.
    """

    def __init__(self, session: Any) -> None:
        """ Initialize files for session.

        :param Session session: session to migrate
        :return None: None
        """

        super().__init__()

        self.session = session

    def read_file(self, local_path: str) -> None:
        """ Read file from session.

        :param str local_path: path to save file to
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Saving to {local_path}...")

        with open(local_path, 'wb') as f:
            tlv = self.session.channel.read()
            size = tlv.get_int(TLV_TYPE_INT)

            if size:
                while size > 0:
                    f.write(self.session.channel.read_raw(TLV_FILE_CHUNK))
                    size -= TLV_FILE_CHUNK

                self.print_success(f"Saved to {local_path}...")
            else:
                error = tlv.get_int(TLV_TYPE_STATUS)

                if error == TLV_STATUS_FAIL:
                    raise RuntimeError("Failed to read file!")

    def send_file(self, local_path: str) -> None:
        """ Send file to session.

        :param str local_path: path to read from
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        with open(local_path, 'rb') as f:
            data = f.read()

            for i in range((len(data) // TLV_FILE_CHUNK) + 1):
                size = i * TLV_FILE_CHUNK
                chunk = data[size:size + TLV_FILE_CHUNK]

                tlv = TLVPacket()
                tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_WAIT)
                tlv.add_raw(TLV_TYPE_FILE, chunk)

                self.session.channel.send(tlv)

            tlv = TLVPacket()
            tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_SUCCESS)

            self.session.channel.send(tlv)
