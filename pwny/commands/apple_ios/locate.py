"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges import Map

from colorscript import ColorScript
from badges.cmd import Command

LOCATE_BASE = 8

LOCATE_GET = tlv_custom_tag(API_CALL_STATIC, LOCATE_BASE, API_CALL)

LOCATE_LONGITUDE = tlv_custom_type(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE)
LOCATE_LATITUDE = tlv_custom_type(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE + 1)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "locate",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage location services.",
            'Usage': "locate",
            'MinArgs': 0,
        })

    def run(self, _):
        result = self.session.send_command(tag=LOCATE_GET)

        latitude = result.get_string(LOCATE_LATITUDE)
        longitude = result.get_string(LOCATE_LONGITUDE)

        plot = Map()
        plot.deploy(float(latitude), float(longitude))

        self.print_empty(plot.get_map())
        self.print_empty(f'%line%boldLatitude%end: {latitude}', start=' ' * 5)
        self.print_empty(f'%line%boldLongitude%end: {longitude}', start=' ' * 5)
        self.print_empty(f'%line%boldMap%end: http://maps.google.com/maps?q={latitude},{longitude}%end', start=' ' * 5)
        self.print_empty()
