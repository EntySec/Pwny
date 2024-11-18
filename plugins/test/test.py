"""
This plugin requires HatSploit: https://hatsploit.netlify.app
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

TEST_TAG = tlv_custom_tag(API_CALL_DYNAMIC, TAB_BASE, API_CALL)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Test Pwny Plugin",
            'Plugin': "test",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - plugin developer'
            ],
            'Description': ""
        })

        self.commands = [
            Command({
                'Name': "test",
                'Description': "Return string from session.",
            })
        ]

    def test(self, _):
        result = self.session.send_command(
            tag=TEST_TAG,
            plugin=self.plugin
        )

        self.print_information(
            result.get_string(TLV_TYPE_STRING))

    def load(self):
        self.print_success("Hello from test!")
