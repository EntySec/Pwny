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
            'Name': "setvol",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Set volume level.",
            'Usage': "setvol {0-10}",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        if argv[1].isdigit():
            level = int(argv[1])

            if level in range(0, 10):
                self.session.send_command(
                    command=argv[0],
                    args=f"{str(level / 10)}",
                    output=False
                )

        self.print_usage(self.details['Usage'])
