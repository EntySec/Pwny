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
            'Name': "localtime",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get current local time.",
            'Usage': "localtime",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=BUILTIN_TIME,
        )

        self.print_empty(result.get_string(TLV_TYPE_STRING))
