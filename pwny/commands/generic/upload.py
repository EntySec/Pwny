"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "transfer",
            'Name': "upload",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Upload local file.",
            'Usage': "upload <local_file> <remote_path>",
            'MinArgs': 2
        }

    def run(self, argc, argv):
        self.session.upload(argv[1], argv[2])
