"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import sys

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_CLIPBOARD_SET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL)
UI_CLIPBOARD_GET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 1)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "clipboard",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Read or write clipboard.",
            'Usage': "clipboard <option>",
            'MinArgs': 1,
            'Options': {
                'read': ['', 'Read from clipboard.'],
                'write': ['', 'Write to clipboard.']
            }
        }

    def run(self, argc, argv):
        if argv[1] == 'read':
            result = self.session.send_command(tag=UI_CLIPBOARD_GET)
            self.print_information(f"Data:%newline{result.get_string(TLV_TYPE_STRING)}")

        elif argv[1] == 'write':
            buffer = ""
            self.print_information("Start typing. Press Ctrl-D to submit.")

            try:
                for line in sys.stdin:
                    buffer += line
            except EOFError:
                pass

            self.session.send_command(
                tag=UI_CLIPBOARD_SET,
                args={
                    TLV_TYPE_STRING: buffer
                }
            )
