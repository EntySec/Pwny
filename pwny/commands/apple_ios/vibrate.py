#!/usr/bin/env python3

#
# This command requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    details = {
        'Category': "misc",
        'Name': "vibrate",
        'Authors': [
            'Ivan Nikolsky (enty8080) - command developer'
        ],
        'Description': "Force device to vibrate.",
        'Usage': "vibrate",
        'MinArgs': 0
    }

    def run(self, argc, argv):
        self.session.send_command(argv[0])
