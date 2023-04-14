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
            'Name': "lchdir",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Change current directory.",
            'Usage': "lchdir",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        os.chdir(argv[1])
        self.print_information(f"Current directory: {os.getcwd()}")
