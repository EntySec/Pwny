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
            'Category': "gather",
            'Name': "whoami",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get current username.",
            'Usage': "whoami",
            'MinArgs': 0
        })

    def run(self, _):
        result = self.session.send_command(
            tag=BUILTIN_WHOAMI,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("???")
            return

        self.print_empty(result.get_string(TLV_TYPE_STRING))
