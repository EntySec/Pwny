"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from textwrap import dedent

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "uuid",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get session uuid real-time.",
            'Usage': "uuid",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(tag=BUILTIN_SYSINFO)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to fetch UUID!")
            return

        self.print_empty(dedent(f"""\
        * UUID:    {result.get_string(TLV_TYPE_UUID)}\
        """))
