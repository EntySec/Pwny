"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
from textwrap import dedent

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "sysinfo",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get session system properties.",
            'Usage': "sysinfo",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        details = self.session.details

        self.badges.print_empty(dedent(f"""
        OS:   {str(details['Platform'])}
        Arch: {str(details['Arch'])}
        """))
