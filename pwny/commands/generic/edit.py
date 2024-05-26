"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import sys
import subprocess

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "filesystem",
            'Name': "edit",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Edit remote file via preferred editor.",
            'Usage': "edit <file> [editor]",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        if argc >= 3:
            editor = argv[2]
        else:
            editor = self.session.get_env('EDITOR') \
                     or os.getenv('EDITOR') \
                     or 'vi'

        file = self.session.loot.random_loot()
        self.session.download(argv[1], file)

        subprocess.run([editor, file])

        self.session.upload(file, argv[1])
        self.session.loot.remove_loot(file)
