"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from textwrap import dedent

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "pid",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get current process ID.",
            'Usage': "pid",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(tag=PROCESS_GET_PID)
        self.print_empty(f"* PID: {str(result.get_int(TLV_TYPE_PID))}")
