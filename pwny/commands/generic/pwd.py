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
            'Name': "pwd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Print current working directory.",
            'Usage': "pwd",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=FS_GETWD,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to get current working directory!")
            return

        self.print_empty(result.get_string(TLV_TYPE_PATH))
