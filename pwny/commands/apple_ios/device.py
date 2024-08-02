"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

GATHER_BASE = 9

GATHER_GET_INFO = tlv_custom_tag(API_CALL_STATIC, GATHER_BASE, API_CALL)

GATHER_NAME = tlv_custom_type(TLV_TYPE_STRING, GATHER_BASE, API_TYPE)
GATHER_OS = tlv_custom_type(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 1)
GATHER_MODEL = tlv_custom_type(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 2)
GATHER_SERIAL = tlv_custom_type(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 3)
GATHER_UDID = tlv_custom_type(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 4)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "device",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get device basic information.",
            'Usage': "device",
            'MinArgs': 0,
        })

    def run(self, _):
        result = self.session.send_command(tag=GATHER_GET_INFO)

        self.print_information(f"Name:    {result.get_string(GATHER_NAME)}")
        self.print_information(f"OS:      iOS {result.get_string(GATHER_OS)}")
        self.print_information(f"Model:   {result.get_string(GATHER_MODEL)}")
        self.print_information(f"Serial:  {result.get_string(GATHER_SERIAL)}")
        self.print_information(f"UDID:    {result.get_string(GATHER_UDID)}")
