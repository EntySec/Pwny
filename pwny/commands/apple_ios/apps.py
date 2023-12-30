"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_APP_LIST = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 9)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "apps",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "List all apps.",
            'Usage': "apps",
            'MinArgs': 0,
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=UI_APP_LIST,
        )

        bundle_id = result.get_string(TLV_TYPE_STRING)
        id = 0

        while bundle_id:
            self.print_information(f"{str(id): <4}: {bundle_id}")
            id += 1
            bundle_id = result.get_string(TLV_TYPE_STRING)
