"""
This plugin requires HatSploit: https://hatsploit.netlify.app
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
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

        self.test_tag = tlv_custom_tag(API_CALL_DYNAMIC, 1, API_CALL)

    def test(self, argc, argv):
        result = self.session.send_command(
            tag=self.test_tag,
        )

        print(result.get_string(TLV_TYPE_STRING))

    def load(self):
        pass
