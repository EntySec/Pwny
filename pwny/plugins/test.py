#!/usr/bin/env python3

#
# This plugin requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.plugin import Plugin


class HatSploitPlugin(Plugin):
    details = {
        'Name': "Test Pwny Plugin",
        'Plugin': "test",
        'Authors': [
            'Ivan Nikolsky (enty8080) - plugin developer'
        ],
        'Description': ""
    }

    commands = {
        'test': {
            'test': {
                'Description': "test",
                'Usage': "test",
                'MinArgs': 1
            }
        }
    }

    def test(self, argc, argv):
        self.print_empty(argc)
        self.print_empty(argv)

    def load(self):
        self.print_empty('test.')
