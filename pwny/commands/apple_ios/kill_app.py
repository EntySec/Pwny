"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

UI_BASE = 6

UI_KILL_APPS = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 3)
UI_KILL_APP = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 4)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "kill_app",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Kill apps.",
            'Usage': "kill_app [bundle]",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        if argc < 2:
            self.print_process("Killing all opened apps...")
            self.session.send_command(tag=UI_KILL_APPS)
            return

        self.print_process(f"Killing {argv[1]}...")
        self.session.send_command(
            tag=UI_KILL_APP,
            args={
                TLV_TYPE_STRING: argv[1]
            }
        )
