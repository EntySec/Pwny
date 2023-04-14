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
            'Name': "say",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Say message from device.",
            'Usage': "say <message>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        command = f"{argv[0]} '{argv[1]}'"
        self.session.send_command(command)
