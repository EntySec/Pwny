"""
This plugin requires HatSploit: https://hatsploit.netlify.app
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.types import *

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

    def test(self, argc, argv):
        result = self.session.send_command(
            pool=self.details['Pool'],
            tag=1
        )

        print(result.get_string(TLV_TYPE_STRING))

    def load(self):
        pass
