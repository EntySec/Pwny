"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from textwrap import dedent

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "sysinfo",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Get session system properties.",
            'Usage': "sysinfo",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(tag=BUILTIN_SYSINFO)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to fetch system information!")
            return

        self.print_empty(dedent(f"""\
        * Name:    {result.get_string(BUILTIN_TYPE_PLATFORM)}
        * Arch:    {result.get_string(BUILTIN_TYPE_ARCH)}
        * Version: {result.get_string(BUILTIN_TYPE_VERSION)}
        * Vendor:  {result.get_string(BUILTIN_TYPE_VENDOR)}
        * UUID:    {self.session.uuid}\
        """))
