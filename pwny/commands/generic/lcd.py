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
            'Name': "lcd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Change local working directory.",
            'Usage': "lcd <path>",
            'MinArgs': 1
        })

    def run(self, args):
        os.chdir(args[1])
