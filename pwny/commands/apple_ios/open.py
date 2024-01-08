"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_OPEN_URL = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 6)
UI_OPEN_APP = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 7)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "open",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Open URL or app.",
            'Usage': "open <option> <arguments>",
            'MinArgs': 2,
            'Options': {
                'url': ['<url>', 'Open URL in default browser.'],
                'app': ['<bundle_id>', 'Open app by bundle id.'],
            }
        }

    def run(self, argc, argv):
        if argv[1] == 'url':
            result = self.session.send_command(
                tag=UI_OPEN_URL,
                args={
                    TLV_TYPE_STRING: argv[2]
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to open URL!")
                return

        elif argv[1] == 'app':
            result = self.session.send_command(
                tag=UI_OPEN_APP,
                args={
                    TLV_TYPE_STRING: argv[2]
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to open app!")
                return
