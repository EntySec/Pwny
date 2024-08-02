"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

UI_BASE = 6

UI_SBINFO = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 8)

UI_LOCKED = tlv_custom_type(TLV_TYPE_INT, UI_BASE, API_TYPE)
UI_PASSCODE = tlv_custom_type(TLV_TYPE_INT, UI_BASE, API_TYPE + 1)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "sbinfo",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get SpringBoard basic information.",
            'Usage': "sbinfo",
            'MinArgs': 0
        })

    def run(self, _):
        result = self.session.send_command(
            tag=UI_SBINFO,
        )

        locked = result.get_int(UI_LOCKED)
        passcode = result.get_int(UI_PASSCODE)

        self.print_information(f"Locked:   {'yes' if locked else 'no'}")
        self.print_information(f"Passcode: {'yes' if passcode else 'no'}")
