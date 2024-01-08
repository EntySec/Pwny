"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "filesystem",
            'Name': "upload",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Upload local file or directory.",
            'Usage': "upload <local_file> <remote_path>",
            'MinArgs': 2
        }

    def run(self, argc, argv):
        if not os.path.isdir(argv[1]):
            self.session.upload(argv[1], argv[2])
            return

        result = self.session.send_command(
            tag=FS_MKDIR,
            args={
                TLV_TYPE_PATH: argv[2]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote path: {argv[2]}: already exists!")
            return

        for root, dirs, files in os.walk(argv[1]):
            local_root = root
            remote_root = root.replace(argv[1], argv[2])

            for dir in dirs:
                self.session.send_command(
                    tag=FS_MKDIR,
                    args={
                        TLV_TYPE_PATH: remote_root + '/' + dir
                    }
                )

            for file in files:
                self.session.upload(local_root + '/' + file, remote_root + '/' + file)