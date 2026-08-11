"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "cp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Copy specific file.",
            'Usage': "cp <src> <dst>",
            'MinArgs': 2
        })

    def run(self, args):
        result = self.session.send_command(
            tag=FS_FILE_COPY,
            args={
                TLV_TYPE_FILENAME: args[1],
                TLV_TYPE_PATH: args[2]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to copy file!")
            return
