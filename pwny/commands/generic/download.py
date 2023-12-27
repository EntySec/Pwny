"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from pwny.api import *
from pwny.types import *

from pex.string import String

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "filesystem",
            'Name': "download",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Download remote file or directory.",
            'Usage': "download <remote_file> <local_path>",
            'MinArgs': 2
        }

        self.string = String()

    def recursive_walk(self, remote_path, local_path):
        result = self.session.send_command(
            tag=FS_LIST,
            args={
                TLV_TYPE_PATH: remote_path
            }
        )

        if result.get_int(TLV_TYPE_STATUS) == TLV_STATUS_SUCCESS:
            if not os.path.isdir(local_path):
                os.mkdir(local_path)

            file = result.get_tlv(TLV_TYPE_GROUP)

            while file:
                try:
                    hash = self.string.bytes_to_stat(file.get_raw(TLV_TYPE_BYTES))
                except Exception:
                    hash = {}

                file_type = self.string.mode_type(hash.get('st_mode', 0))
                path = file.get_string(TLV_TYPE_PATH)

                if file_type == 'file':
                    self.session.download(
                        path, local_path + '/' + os.path.split(path)[1])

                elif file_type == 'directory':
                    self.recursive_walk(
                        path, local_path + '/' + os.path.split(path)[1])

                file = result.get_tlv(TLV_TYPE_GROUP)

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=FS_STAT,
            args={
                TLV_TYPE_PATH: argv[1]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote file: {argv[1]}: does not exist!")
            return

        try:
            hash = self.string.bytes_to_stat(result.get_raw(TLV_TYPE_BYTES))
        except Exception:
            hash = {}

        file_type = self.string.mode_type(hash.get('st_mode', 0))

        if file_type != 'directory':
            self.session.download(argv[1], argv[2])
        else:
            self.recursive_walk(argv[1], argv[2])
