"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from pwny.types import *
from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "generic",
            'Name': "test",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Test.",
            'Usage': "test",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(pool=TLV_POOL_PEX, tag=0)
        print(result.get_string(TLV_TYPE_STRING))
