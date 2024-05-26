"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "gather",
            'Name': "ps",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get list of processes.",
            'Usage': "ps",
            'MinArgs': 0
        }

    def run(self, argc, argv):
        result = self.session.send_command(tag=PROCESS_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to fetch process list!")
            return

        process = result.get_tlv(TLV_TYPE_GROUP)
        headers = ('PID', 'CPU', 'Name', 'Path')
        data = []

        while process:
            data.append((
                process.get_int(TLV_TYPE_PID),
                process.get_string(PROCESS_TYPE_PID_CPU),
                process.get_string(PROCESS_TYPE_PID_NAME),
                process.get_string(PROCESS_TYPE_PID_PATH)
            ))

            process = result.get_tlv(TLV_TYPE_GROUP)

        self.print_table('Process List', headers, *sorted(data))
