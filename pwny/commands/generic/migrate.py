"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.migrate import Migrate

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "evasion",
            'Name': "migrate",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Migrate into a process.",
            'Usage': "migrate <pid>",
            'MinArgs': 1
        })

    def run(self, _):
        self.print_error("Migration is not implemented yet!")
