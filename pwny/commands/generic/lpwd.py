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
            'Name': "lpwd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get local working directory.",
            'Usage': "lpwd",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        self.print_information(os.getcwd())
