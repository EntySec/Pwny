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
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Migrate into a process by ID.",
            'Usage': "migrate",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        migrate = Migrate(session=self.session)
        migrate.migrate(argv[1])
