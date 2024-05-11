"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "evasion",
            'Name': "unsecure",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Disable all TLS security layers.",
            'Usage': "unsecure",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        self.session.send_command(
            tag=BUILTIN_UNSECURE
        )

        self.session.channel.secure = False
