"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from pex.string import String
from badges.cmd import Command


class ExternalCommand(Command, String):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "find",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Search for file or directory.",
            'Usage': "find <where> <what> <start_date> <end_date>",
            'MinArgs': 4
        })

    def run(self, args):
        result = self.session.send_command(
            tag=FS_FIND,
            args={
                TLV_TYPE_PATH: args[1],
                TLV_TYPE_FILENAME: args[2],
                FS_TYPE_START_DATE: start,
                FS_TYPE_END_DATE: end
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote file: {args[1]}: does not exist!")
            return

        stat = result.get_tlv(TLV_TYPE_GROUP)
        headers = ('Mode', 'Size', 'Type', 'Modified', 'Root', 'Name')
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
            file_path = stat.get_string(TLV_TYPE_PATH)

            data.append((file_mode, file_size, file_type,
                         file_time, file_path, file_name))
            stat = result.get_tlv(TLV_TYPE_GROUP)

        self.print_table(f'Results: {args[2]}', headers, *sorted(data))

