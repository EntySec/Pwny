#!/usr/bin/env python3

#
# This plugin requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.plugin import Plugin


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "Test Pwny Plugin",
            'Plugin': "test",
            'Authors': [
                'Ivan Nikolsky (enty8080) - plugin developer'
            ],
            'Pool': 2,
            'Description': ""
        }

        self.commands = {
            'test': {
                'test': {
                    'Description': "test",
                    'Usage': "test",
                    'MinArgs': 0
                }
            }
        }

        self.pool = {
            2: {
                'test': 1
            }
        }

    def test(self, argc, argv):
        self.print_empty(self.session.send_command(
            'test', output=True, pool=self.pool))

    def load(self):
        pass
