"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "local",
            'Name': "lpwd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get local working directory.",
            'Usage': "lpwd",
            'MinArgs': 0
        })

    def run(self, _):
        self.print_empty(os.getcwd())
