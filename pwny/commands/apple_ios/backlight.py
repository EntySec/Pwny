"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_BACKLIGHT_SET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 2)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "backlight",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Set backlight level.",
            'Usage': "backlight [0-10]",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        self.session.send_command(
            tag=UI_BACKLIGHT_SET,
            args={
                TLV_TYPE_INT: int(argv[1])
            }
        )
