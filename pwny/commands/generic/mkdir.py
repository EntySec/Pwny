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
            'Name': "mkdir",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Create a directory.",
            'Usage': "mkdir <path>",
            'MinArgs': 1
        })

    def run(self, args):
        result = self.session.send_command(
            tag=FS_MKDIR,
            args={
                TLV_TYPE_PATH: args[1]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote directory: {args[1]}: failed to create!")
            return
