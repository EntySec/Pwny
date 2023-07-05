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

from badges import Badges

from pex.fs import FS
from pex.proto.channel import ChannelClient

from typing import NamedTuple


class TLVPacket(NamedTuple):
    scope: int
    tag: int
    status: int
    size: int
    data: bytes


class TLV(Badges, FS):
    def __init__(self):
        super().__init__()

        self.tlv_stdapi = 0

        self.tlv_short = 2
        self.tlv_int = 4

        self.tlv_success = 0
        self.tlv_fail = 1
        self.tlv_wait = 2
        self.tlv_not_implemented = 3
        self.tlv_usage_error = 4
        self.tlv_rw_error = 5
        self.tlv_not_loaded = 6

        self.endian = 'little'

        self.tlv_api_calls = {
            0: {
                'exit': 0,
                'push': 1,
                'pull': 2,
            }
        }

    def tlv_send_packet(self, channel: ChannelClient, tlv_packet: TLVPacket) -> None:
        """ Send TLV packet to channel.

        :param ChannelClient channel: channel to send TLV packet to
        :param TLVPacket tlv_packet: TLV packet
        :return None: None
        """

        channel.send(int.to_bytes(tlv_packet.scope, self.tlv_short, self.endian))
        channel.send(int.to_bytes(tlv_packet.tag, self.tlv_short, self.endian))
        channel.send(int.to_bytes(tlv_packet.status, self.tlv_short, self.endian))
        channel.send(int.to_bytes(tlv_packet.size, self.tlv_int, self.endian))

        if tlv_packet.size > 0:
            channel.send(tlv_packet.data)

    def tlv_send_file(self, channel: ChannelClient, local_file: str, remote_path: str) -> None:
        """ Send file to channel.

        :param ChannelClient channel: channel to send file to
        :param str local_file: file to send to the channel
        :param str remote_path: path to save file to
        :return None: None
        """

        exists, is_dir = self.exists(local_file)

        if exists or not is_dir:
            push_api_call = self.tlv_api_calls[self.tlv_stdapi]['push']

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=push_api_call,
                status=self.tlv_success,
                size=len(config),
                data=b""
            ))

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=push_api_call,
                status=self.tlv_success,
                size=len(remote_path),
                data=remote_path.encode()
            ))

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=push_api_call,
                status=self.tlv_success,
                size=len(local_file),
                data=local_file.encode()
            ))

            tlv_packet = self.tlv_read_packet(channel)

            if tlv_packet.tag == push_api_call and tlv_packet.status == self.tlv_success:
                self.print_process(f"Uploading {local_file}...")

                with open(local_file, 'rb') as f:
                    data = f.read()

                    for i in range((len(data) // 1024) + 1):
                        size = i * 1024
                        chunk = data[size:size + 1024]

                        self.tlv_send_packet(channel, TLVPacket(
                            scope=tlv_packet.scope,
                            tag=tlv_packet.tag,
                            status=self.tlv_wait,
                            size=len(chunk),
                            data=chunk
                        ))

                self.tlv_send_packet(channel, TLVPacket(
                    scope=self.tlv_stdapi,
                    tag=push_api_call,
                    status=tlv_packet.status,
                    size=0,
                    data=b""
                ))

                tlv_packet = self.tlv_read_packet(channel)

                if tlv_packet.tag == push_api_call and tlv_packet.status == self.tlv_success:
                    self.print_success(f"Saved to {remote_path}!")
                    return True

            self.print_error(f"{tlv_packet.data.decode()}!")
            return False

        self.print_error(f"Local file: {local_file}: does not exist!")
        return False

    def tlv_read_packet(self, channel: ChannelClient) -> TLVPacket:
        """ Read TLV packet from channel.

        :param ChannelClient channel: channel to read TLV packet from
        :return TLVPacket: TLV packet
        """

        scope = int.from_bytes(channel.read(self.tlv_short), self.endian)
        tag = int.from_bytes(channel.read(self.tlv_short), self.endian)
        status = int.from_bytes(channel.read(self.tlv_short), self.endian)
        size = int.from_bytes(channel.read(self.tlv_int), self.endian)
        data = channel.read(size)

        return TLVPacket(scope, tag, status, size, data)

    def tlv_read_file(self, channel: ChannelClient, remote_file: str, local_path: str) -> bool:
        """ Read file from channel.

        :param ChannelClient channel: channel to read file from
        :param str remote_file: remote file to read from channel
        :param str local_path: local path to save remote file to
        :return bool: True if success else False
        """

        exists, is_dir = self.exists(local_path)

        if exists:
            if is_dir:
                local_path = local_path + '/' + os.path.split(remote_file)[1]

            pull_api_call = self.tlv_api_calls[self.tlv_stdapi]['pull']

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=pull_api_call,
                status=self.tlv_success,
                size=len(config),
                data=config
            ))

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=pull_api_call,
                status=self.tlv_success,
                size=len(local_path),
                data=local_path.encode()
            ))

            self.tlv_send_packet(channel, TLVPacket(
                scope=self.tlv_stdapi,
                tag=pill_api_call,
                status=self.tlv_success,
                size=len(remote_file),
                data=remote_file.encode()
            ))

            tlv_packet = self.tlv_read_packet(channel)

            if tlv_packet.tag == pull_api_call and tlv_packet.status == self.tlv_success:
                self.print_process(f"Downloading {remote_file}...")

                with open(local_path, 'wb') as f:
                    tlv_packet = self.tlv_read_packet(channel)

                    while tlv_packet.status == self.tlv_wait:
                        f.write(tlv_packet.data)
                        tlv_packet = self.tlv_read_packet(channel)

                self.print_success(f"Saved to {local_path}!")
                return True

            self.print_error(f"{tlv_packet.data.decode()}!")
            return False

        self.print_error(f"Local path: {local_path}: does not exist!")
        return False
