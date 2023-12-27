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
            'Name': "rm",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Delete file or directory.",
            'Usage': "rm [-r] <path>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        if argc < 3:
            result = self.session.send_command(
                tag=FS_FILE_DELETE,
                args={
                    TLV_TYPE_PATH: argv[1],
                }
            )
        else:
            result = self.session.send_command(
                tag=FS_DIR_DELETE,
                args={
                    TLV_TYPE_PATH: argv[2]
                }
            )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to delete path specified!")
            return
