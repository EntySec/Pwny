"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_SAY = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 5)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "say",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Say something.",
            'Usage': "say <message>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        self.session.send_command(
            tag=UI_SAY,
            args={
                TLV_TYPE_STRING: argv[1]
            }
        )
