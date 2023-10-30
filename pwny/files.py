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

from pwny.__main__ import Pwny

from pwny.types import *
from pwny.api import *

from badges import Badges

from pex.fs import FS
from pex.proto.tlv import TLVPacket


class Files(Pwny, Badges, FS):
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

    def read_file(self, remote_file: str, local_path: str) -> bool:
        """ Read file from session.

        :param str remote_file: remote file path
        :param str local_path: path to save file to
        :return bool: True if success else False
        """

        self.print_process(f"Downloading {remote_file}...")

        tlv = TLVPacket()

        tlv.add_int(TLV_TYPE_TAG, API_PULL)
        tlv.add_string(TLV_TYPE_STRING, remote_file)
        self.session.channel.send(tlv)

        tlv = self.session.channel.read()

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_ENOENT:
            self.print_error(f"Remote file: {remote_file}: does not exist!")

            self.session.channel.read()
            return False

        exists, is_dir = self.exists(local_path)

        if exists:
            if is_dir:
                local_path = os.path.abspath(
                    '/'.join(
                        (local_path, os.path.split(remote_file)[1])
                    )
                )

            try:
                with open(local_path, 'wb') as f:
                    tlv = TLVPacket()
                    tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_SUCCESS)
                    self.session.channel.send(tlv)

                    self.print_process(f"Saving to {local_path}...")

                    while True:
                        tlv = self.session.channel.read()
                        status = tlv.get_int(TLV_TYPE_STATUS)

                        if status != TLV_STATUS_WAIT:
                            break

                        f.write(tlv.get_raw(TLV_TYPE_FILE))

                    if status == TLV_STATUS_SUCCESS:
                        self.print_success(f"Saved to {local_path}!")
                        return True

                    self.print_error(f"Failed to save file to {local_path}!")
                    return False

            except Exception as e:
                self.print_warning(f"Possible cause: {str(e)}.")

        tlv = TLVPacket()

        tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_ENOENT)

        self.session.channel.send(tlv)
        self.session.channel.read()

        self.print_error(f"Local path: {local_path}: does not exist!")
        return False

    def send_file(self, local_file: str, remote_path: str) -> bool:
        """ Send file to session.

        :param str local_file: path to read from
        :param str remote_path: path to save uploaded file to
        :return bool: True if success else False
        """

        self.print_process(f"Uploading {local_file}...")

        tlv = TLVPacket()

        tlv.add_int(TLV_TYPE_TAG, API_PUSH)
        tlv.add_string(TLV_TYPE_STRING, remote_path)
        self.session.channel.send(tlv)

        exists, is_dir = self.exists(local_file)

        if exists and not is_dir:
            try:
                with open(local_file, 'rb') as f:
                    tlv = TLVPacket()

                    tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_SUCCESS)
                    self.session.channel.send(tlv)

                    tlv = self.session.channel.read()
                    if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_ENOENT:
                        self.print_error(f"Remote path: {remote_path}: does not exist!")

                        self.session.channel.read()
                        return False

                    self.print_process(f"Saving to {remote_path}...")

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

                    tlv = self.session.channel.read()
                    if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_SUCCESS:
                        self.print_success(f"Saved to {remote_path}!")
                        return True

                    self.print_error(f"Failed to save file to {remote_path}!")
                    return False

            except Exception as e:
                self.print_warning(f"Possible cause: {str(e)}.")

        tlv = TLVPacket()

        tlv.add_int(TLV_TYPE_STATUS, TLV_STATUS_ENOENT)

        self.session.channel.send(tlv)
        self.session.channel.read()

        self.print_error(f"Local file: {local_file}: does not exist!")
        return False
