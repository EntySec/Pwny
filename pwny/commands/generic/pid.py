"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from textwrap import dedent

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "pid",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get current process ID.",
        })

    def run(self, _):
        result = self.session.send_command(tag=PROCESS_GET_PID)
        self.print_information(f"PID: {str(result.get_int(TLV_TYPE_PID))}")
