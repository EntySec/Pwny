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
            'Name': "cd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Change current directory.",
            'Usage': "cd <path>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=FS_CHDIR,
            args={
                TLV_TYPE_PATH: argv[1],
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to change current directory!")
            return
