"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pex.string import String

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "filesystem",
            'Name': "list",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get contents of a directory.",
            'Usage': "list [path]",
            'MinArgs': 0
        }

        self.string = String()

    def run(self, argc, argv):
        if argc >= 2:
            path = argv[1]
        else:
            path = '.'

        result = self.session.send_command(
            tag=FS_LIST,
            args={
                TLV_TYPE_PATH: path,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to fetch files list!")
            return

        stat = result.get_tlv(TLV_TYPE_GROUP)
        headers = ('Mode', 'Size', 'Type', 'Modified', 'Name')
        data = []

        while stat:
            buffer = stat.get_raw(TLV_TYPE_BYTES)
            hash = self.string.bytes_to_stat(buffer)

            file_size = self.string.size_normalize(hash.get('st_size', 0))
            file_mode = self.string.mode_symbolic(hash.get('st_mode', 0))
            file_type = self.string.mode_type(hash.get('st_mode', 0))
            file_time = self.string.time_normalize(hash.get('st_atime', 0))
            file_name = stat.get_string(TLV_TYPE_FILENAME)

            data.append((file_mode, file_size, file_type, file_time, file_name))
            stat = result.get_tlv(TLV_TYPE_GROUP)

        self.print_table(f'Listing: {path}', headers, *sorted(data))
