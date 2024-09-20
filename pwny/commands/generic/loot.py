"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "loot",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage collected loot.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List all collected loot.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-r', '--remove'),
                    {
                        'help': "Remove collected loot by name.",
                        'metavar': 'NAME'
                    }
                ),
                (
                    ('-w', '--wipe'),
                    {
                        'help': "Wipe all collected loot.",
                        'action': 'store_true'
                    }
                )
            ]
        })

    def run(self, args):
        if args.remove:
            self.session.loot.remove_loot(args.remove)

        elif args.wipe == '-w':
            for loot in self.session.loot.list_loot():
                self.session.loot.remove_loot(loot[0])

        elif args.list == '-l':
            loot_data = self.session.loot.list_loot()

            if not loot_data:
                self.print_warning("No loot has been collected yet.")
                return

            self.print_table("Loot", ('Name', 'Path', 'Time'),
                             *loot_data)
