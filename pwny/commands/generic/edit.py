"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import sys
import subprocess

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "edit",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Edit remote file via preferred editor.",
            'Usage': "edit <file> [editor]",
            'MinArgs': 1
        })

    def run(self, args):
        if len(args) >= 3:
            editor = args[2]
        else:
            editor = self.session.console.get_env('EDITOR') \
                     or os.getenv('EDITOR') \
                     or 'vi'

        file = self.session.loot.random_loot()
        self.session.download(args[1], file)

        subprocess.run([editor, file])

        self.session.upload(file, args[1])
        self.session.loot.remove_loot(file)
