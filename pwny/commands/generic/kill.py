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
            'Category': "manage",
            'Name': "kill",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Kill process by ID.",
            'Usage': "kill <id>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=PROCESS_KILL,
            args={
                TLV_TYPE_PID: argv[1]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Failed to kill process {str(argv[1])}!")
            return
