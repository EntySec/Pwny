"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "misc",
            'Name': "exec",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Execute system command.",
            'Usage': "exec <command>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        command = f"{argv[0]} {argv[1]}"
        output = self.session.send_command(command, True)

        if output:
            self.print_empty(output)
