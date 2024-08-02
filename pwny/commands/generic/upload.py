"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "upload",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Upload local file or directory.",
            'Usage': "upload <local_file> <remote_path>",
            'MinArgs': 2
        })

    def run(self, args):
        if not os.path.isdir(args[1]):
            self.session.upload(args[1], args[2])
            return

        result = self.session.send_command(
            tag=FS_MKDIR,
            args={
                TLV_TYPE_PATH: args[2]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote path: {args[2]}: already exists!")
            return

        for root, dirs, files in os.walk(args[1]):
            local_root = root
            remote_root = root.replace(args[1], args[2])

            for dir in dirs:
                self.session.send_command(
                    tag=FS_MKDIR,
                    args={
                        TLV_TYPE_PATH: remote_root + '/' + dir
                    }
                )

            for file in files:
                self.session.upload(local_root + '/' + file, remote_root + '/' + file)