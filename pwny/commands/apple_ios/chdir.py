"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    details = {
        'Category': "filesystem",
        'Name': "chdir",
        'Authors': [
            'Ivan Nikolsky (enty8080) - command developer'
        ],
        'Description': "Change current working directory.",
        'Usage': "chdir <path>",
        'MinArgs': 1
    }

    def run(self, argc, argv):
        command = f"{argv[0]} {argv[1]}"
        output = self.session.send_command(command, True)

        if output:
            self.print_empty(output)
