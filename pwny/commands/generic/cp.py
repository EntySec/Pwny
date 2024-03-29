"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "filesystem",
            'Name': "cp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Copy specific file.",
            'Usage': "cp <src> <dst>",
            'MinArgs': 2
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=FS_FILE_COPY,
            args={
                TLV_TYPE_FILENAME: argv[1],
                TLV_TYPE_PATH: argv[2]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to copy file!")
            return
