"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.migrate import Migrate

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "evasion",
            'Name': "migrate",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Migrate into a process by ID.",
            'Usage': "migrate <pid>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        self.print_error("Migration is not implemented yet!")
