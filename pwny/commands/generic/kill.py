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
            'Category': "manage",
            'Name': "kill",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Kill process by ID.",
            'Usage': "kill <id>",
            'MinArgs': 1
        })

    def run(self, args):
        if not args[1].isdigit():
            self.print_warning("Not and ID, use %greenkillall%end for name instead.")
            return

        result = self.session.send_command(
            tag=PROCESS_KILL,
            args={
                TLV_TYPE_PID: int(args[1])
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Process ID: {str(args[1])}: does not exist!")
            return
