"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "loot",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage collected loot.",
            'Usage': "loot <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                '-l': ['', 'List all collected loot.'],
                '-r': ['<name>', 'Remove collected loot.'],
                '-w': ['', 'Wipe all collected loot.']
            }
        }

    def run(self, argc, argv):
        if argv[1] == '-r':
            self.session.loot.remove_loot(argv[2])

        elif argv[1] == '-w':
            for loot in self.session.loot.list_loot():
                self.session.loot.remove_loot(loot[0])

        elif argv[1] == '-l':
            loot_data = self.session.loot.list_loot()

            if not loot_data:
                self.print_warning("No loot has been collected yet.")
                return

            self.print_table("Loot", ('Name', 'Path', 'Time'),
                             *loot_data)
