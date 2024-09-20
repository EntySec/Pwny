"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pex.string import String

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command, String):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "list",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "List contents of a directory.",
            'Usage': "list [path]",
            'MinArgs': 0
        })

    def run(self, args):
        if len(args) >= 2:
            path = args[1]
        else:
            path = '.'

        result = self.session.send_command(
            tag=FS_LIST,
            args={
                TLV_TYPE_PATH: path,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote directory: {path}: does not exist!")
            return

        stat = result.get_tlv(TLV_TYPE_GROUP)
        headers = ('Mode', 'Size', 'Type', 'Modified', 'Name')
        data = []

        while stat:
            buffer = stat.get_raw(TLV_TYPE_BYTES)
            try:
                hash = self.bytes_to_stat(buffer)
            except Exception:
                hash = {}

            file_size = self.size_normalize(hash.get('st_size', 0))
            file_mode = self.mode_symbolic(hash.get('st_mode', 0))
            file_type = self.mode_type(hash.get('st_mode', 0))
            file_time = self.time_normalize(hash.get('st_mtime', 0))
            file_name = stat.get_string(TLV_TYPE_FILENAME)

            data.append((file_mode, file_size, file_type, file_time, file_name))
            stat = result.get_tlv(TLV_TYPE_GROUP)

        self.print_table(f'Listing: {path}', headers, *sorted(data))
