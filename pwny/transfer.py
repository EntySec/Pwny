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

    def pull(self, channel: ChannelSocket, remote_file: str, local_path: str) -> bool:
        """ Pull file from the channel.

        :param ChannelSocket channel: channel to pull file from
        :param str remote_file: file to pull
        :param str local_path: path to save pulled file to
        """

        request = json.dumps({
            'cmd': "download",
            'args': remote_file,
            'token': ''
        })

        response = json.loads(channel.send_command(request))
        status = int(response['status'])

        if status == 1:
            if 'size' in response:
                exists, is_dir = self.exists(local_path)
                if exists:
                    if is_dir:
                        local_path = local_path + '/' + os.path.split(remote_file)[1]

                    self.print_process(f"Downloading {remote_file}...")

                    size = int(result['size'])
                    token = self.random_string(8).encode()

                    channel.send(token)

                    with open(local_path, 'wb') as f:
                        while True:
                            chunk = channel.read(1024)

                            if token in chunk:
                                f.write(chunk.replace(token, b''))
                                break

                            f.write(chunk)
                    return True

        elif status == 0:
            self.print_error(f"Remote file: {remote_file}: does not exist!")
        elif status == 2:
            self.print_error(f"Remote path: {remote_file}: is a directory!")
        else:
            self.print_error("Implementation error: download: is not implemented!")

        return False

    def push(self, channel: ChannelSocket, local_file: str, remote_path: str) -> bool:
        """ Push file to the channel.

        :param ChannelSocket channel: channel to push file to
        :param str local_file: file to push
        :param str remote_path: path to save pushed file to
        """

        if self.exists(local_file):
            with open(local_file, 'rb') as f:
                data = f.read()
                size = len(data)
                name = os.path.split(local_file)[1]

                request = json.dumps({
                    'cmd': 'upload',
                    'args': json.dumps({
                        'size': size,
                        'path': remote_path,
                        'name': name
                    }),
                    'token': ''
                })

                channel.send_command(request, False)

            token = self.random_string(8).encode()

            for i in range((size // 1024) + 1):
                deltax = i * 1024
                chunk = data[deltax:deltax + 1024]
                channel.send(chunk)

            channel.send(token)
            return True

        return False
