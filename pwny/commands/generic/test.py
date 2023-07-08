"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "local",
            'Name': "tests",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "",
            'Usage': "tests",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        self.print_information(self.session.send_command("test", output=True))
