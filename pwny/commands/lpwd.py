#!/usr/bin/env python3

#
# This command requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

import os

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    details = {
        'Category': "local",
        'Name': "lpwd",
        'Authors': [
            'Ivan Nikolsky (enty8080) - command developer'
        ],
        'Description': "Get local current directory.",
        'Usage': "lpwd",
        'MinArgs': 0
    }

    def run(self, argc, argv):
        self.print_information(f"Current directory: {os.getcwd()}")
