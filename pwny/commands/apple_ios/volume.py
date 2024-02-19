"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_VOLUME_SET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 10)
UI_VOLUME_GET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 11)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "volume",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage volume level.",
            'Usage': "volume <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                'get': ['', 'Get volume level.'],
                'set': ['[0-10]', 'Set volume level.'],
            }
        }

    def run(self, argc, argv):
        if argv[1] == 'get':
            result = self.session.send_command(tag=UI_VOLUME_GET)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to get volume level!")
                return

            self.print_information(f"Volume level: {str(result.get_int(TLV_TYPE_INT))}")
            return

        if argv[1] == 'set':
            result = self.session.send_command(
                tag=UI_VOLUME_SET,
                args={
                    TLV_TYPE_INT: int(argv[2])
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to set volume level!")
                return
