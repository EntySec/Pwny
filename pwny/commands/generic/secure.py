"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "evasion",
            'Name': "secure",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Secure communication with TLS.",
            'Usage': "secure",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        self.session.secure()
