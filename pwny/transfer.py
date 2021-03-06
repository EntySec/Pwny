"""
MIT License

Copyright (c) 2020-2022 EntySec

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
import json

from hatsploit.core.cli.badges import Badges

from pex.fs import FS
from pex.string import String
from pex.proto.channel import ChannelSocket


class Transfer(Badges, FS, String):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    implementations of file transfer methods for the Pwny session.
    """

    def pull(self, channel: ChannelSocket, remote_file: str, local_path: str) -> None:
        """ Pull file from the channel.

        :param ChannelSocket channel: channel to pull file from
        :param str remote_file: file to pull
        :param str local_path: path to save pulled file to
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        request = json.dumps({
            'cmd': "download",
            'args': remote_file,
            'token': ''
        })

        data = channel.send_command(request)

        if data == 'file':
            exists, is_dir = self.exists(local_path)
            if exists:
                if is_dir:
                    local_path = local_path + '/' + os.path.split(remote_file)[1]

                self.print_process(f"Downloading {remote_file}...")

                token = self.random_string(8)
                channel.send_command(token, False)

                with open(local_path, 'wb') as f:
                    while True:
                        chunk = channel.read(1024)

                        if token.encode() in chunk:
                            token_index = chunk.index(token.encode())
                            token_size = len(token)
                            f.write(chunk[:token_index])

                            break

                        f.write(chunk)

                self.print_success(f"Saved to {local_path}!")
                return

        if data == 'directory':
            raise RuntimeError(f"Remote file: {remote_file}: is a directory!")

        if data == 'incorrect':
            raise RuntimeError(f"Remote file: {remote_file}: does not exist!")

        raise RuntimeError("Implementation error: download: not implemented!")

    def push(self, channel: ChannelSocket, local_file: str, remote_path: str) -> None:
        """ Push file to the channel.

        :param ChannelSocket channel: channel to push file to
        :param str local_file: file to push
        :param str remote_path: path to save pushed file to
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.exists(local_file):
            entry_token = self.random_string(8)

            request = json.dumps({
                'cmd': "upload",
                'args': remote_path,
                'token': entry_token
            })

            data = channel.send_command(request)

            if data == 'directory':
                remote_path = remote_path + '/' + os.path.split(local_file)[1]
                channel.send_command(remote_path, False)

            elif data != 'file':
                raise RuntimeError("Implementation error: upload: not implemented!")

            self.print_process(f"Uploading {local_file}...")

            token = self.random_string(8)
            status = channel.send_command(token)

            if status == 'success':
                with open(local_file, 'rb') as f:
                    data = f.read()

                    max_size = 1024
                    size = len(data)

                    num_parts = int(size / max_size) + 1
                    for i in range(0, num_parts):
                        current = i * max_size
                        block = data[current:current + max_size]

                        if block:
                            channel.send(block)

                status = channel.send_command(token)
                if status == entry_token:
                    self.print_success(f"Saved to {remote_path}!")
                    return

                raise RuntimeError(f"Failed to save to {remote_path}!")
            raise RuntimeError(f"Remote directory: {os.path.split(remote_path)[0]}: does not exist!")
