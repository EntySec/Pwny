"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "fs",
            'Name': "rpwd",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get remote working directory.",
            'Usage': "rpwd",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        dir = self.session.send_command("getwd", output=True)
        self.print_information(f"Remote working directory: {dir}.")
