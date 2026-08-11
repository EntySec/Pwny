"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

UI_BASE = 6

UI_VOLUME_SET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 10)
UI_VOLUME_GET = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 11)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "UI",
            'Name': "volume",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage volume level.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-g', '--get'),
                    {
                        'help': 'Display volume level.',
                        'action': 'store_true'
                    }
                ),
                (
                    ('-s', '--set'),
                    {
                        'help': 'Set volume level.',
                        'metavar': '[0-10]',
                        'type': int,
                        'choices': range(0, 11)
                    }
                )
            ]
        })

    def run(self, args):
        if args.get:
            result = self.session.send_command(tag=UI_VOLUME_GET)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to get volume level!")
                return

            self.print_information(f"Volume level: {str(result.get_int(TLV_TYPE_INT))}")
            return

        if args.set:
            result = self.session.send_command(
                tag=UI_VOLUME_SET,
                args={
                    TLV_TYPE_INT: args.set
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to set volume level!")
                return
