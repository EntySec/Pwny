"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import sys

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "cat",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Read specific file.",
            'Usage': "cat <file>",
            'MinArgs': 1
        })

    def run(self, args):
        pipes = self.session.pipes

        try:
            pipe_id = pipes.create_pipe(
                pipe_type=FS_PIPE_FILE,
                args={
                    TLV_TYPE_FILENAME: args[1],
                    FS_TYPE_MODE: 'rb',
                }
            )
        except RuntimeError:
            self.print_error(f"Remote file: {args[1]}: does not exist!")
            return

        pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 2)
        size = pipes.tell_pipe(FS_PIPE_FILE, pipe_id)
        pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 0)

        while size > 0:
            chunk = min(TLV_FILE_CHUNK, size)
            buffer = pipes.read_pipe(FS_PIPE_FILE, pipe_id, chunk)

            sys.stdout.write(buffer.decode(errors='ignore'))
            sys.stdout.flush()

            size -= chunk

        pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)
