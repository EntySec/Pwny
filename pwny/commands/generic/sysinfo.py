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
                'Ivan Nikolskiy (enty8080) - command developer'
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

        self.print_information(f"Name:    {result.get_string(BUILTIN_TYPE_PLATFORM)}")
        self.print_information(f"Arch:    {result.get_string(BUILTIN_TYPE_ARCH)}")
        self.print_information(f"Version: {result.get_string(BUILTIN_TYPE_VERSION)}")
        self.print_information(f"Vendor:  {result.get_string(BUILTIN_TYPE_VENDOR)}")
        self.print_information(f"UUID:    {self.session.uuid}")
