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
            'Name': "chmod",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Change path permissions.",
            'Usage': "chmod <mode> <path>",
            'MinArgs': 2
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=FS_CHMOD,
            args={
                FS_TYPE_MODE: argv[1],
                TLV_TYPE_PATH: argv[2],
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to set path permissions!")
            return
