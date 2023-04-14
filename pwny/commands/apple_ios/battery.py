"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "battery",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Show battery status.",
            'Usage': "battery",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        output = self.session.send_command(argv[0], True)

        if output:
            self.print_empty(output)
