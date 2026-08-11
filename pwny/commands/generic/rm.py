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
            'Name': "rm",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Delete file.",
            'Usage': "rm <path>",
            'MinArgs': 1
        })

    def run(self, args):
        result = self.session.send_command(
            tag=FS_FILE_DELETE,
            args={
                TLV_TYPE_PATH: args[1],
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote file: {args[1]}: does not exist!")
            return
