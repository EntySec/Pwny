"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

TOKEN_BASE = 21

TOKEN_GETUID = tlv_custom_tag(API_CALL_STATIC, TOKEN_BASE, API_CALL + 2)

TLV_TYPE_TOKEN_USER = tlv_custom_type(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "getuid",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Get current effective user identity (reflects impersonation).",
        })

    def run(self, _):
        result = self.session.send_command(tag=TOKEN_GETUID)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to get current user identity!")
            return

        user = result.get_string(TLV_TYPE_TOKEN_USER)
        if user:
            self.print_information(user)
        else:
            self.print_warning("Could not determine user identity.")
