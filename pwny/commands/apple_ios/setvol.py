"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    details = {
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
                command = f"{argv[0]} {str(level / 10)}"
                self.session.send_command(command)

         self.print_usage(self.details['Usage'])
