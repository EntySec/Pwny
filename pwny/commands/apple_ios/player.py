"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import sys

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

PLAYER_BASE = 7

PLAYER_INFO = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL)
PLAYER_PLAY = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 1)
PLAYER_PAUSE = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 2)
PLAYER_NEXT = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 3)
PLAYER_BACK = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 4)

PLAYER_PIPE_WAVE = tlv_custom_pipe(PIPE_STATIC, PLAYER_BASE, PIPE_TYPE)

PLAYER_TITLE = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE)
PLAYER_ALBUM = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE + 1)
PLAYER_ARTIST = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE + 2)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "player",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage media player.",
            'Usage': "player <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                'info': ['', 'Get current playing song.'],
                'play': ['', 'Play the current song.'],
                'pause': ['', 'Pause the current song.'],
                'next': ['', 'Play next song.'],
                'back': ['', 'Play previous song.'],
                'wave': ['<file>', 'Play audio from file.'],
            }
        })

    def run(self, args):
        if args[1] == 'info':
            result = self.session.send_command(tag=PLAYER_INFO)

            self.print_information(f"Title:  {result.get_string(PLAYER_TITLE)}")
            self.print_information(f"Album:  {result.get_string(PLAYER_ALBUM)}")
            self.print_information(f"Artist: {result.get_string(PLAYER_ARTIST)}")

        elif args[1] == 'wave':
            with open(args[2], 'rb') as f:
                self.print_process("Playing audio wave...")

                try:
                    pipe_id = self.session.pipes.create_pipe(
                        pipe_type=PLAYER_PIPE_WAVE,
                        args={
                            TLV_TYPE_BYTES: f.read()
                        }
                    )

                except RuntimeError:
                    self.print_error("Failed to send audio file!")
                    return

                self.print_information("Press Ctrl-C to stop.")

                try:
                    for _ in sys.stdin:
                        pass

                except KeyboardInterrupt:
                    self.print_process("Stopping...")

                self.session.pipes.destroy_pipe(
                    pipe_type=PLAYER_PIPE_WAVE,
                    pipe_id=pipe_id
                )

        elif args[1] == 'play':
            self.session.send_command(tag=PLAYER_PLAY)

        elif args[1] == 'pause':
            self.session.send_command(tag=PLAYER_PAUSE)

        elif args[1] == 'next':
            self.session.send_command(tag=PLAYER_NEXT)

        elif args[1] == 'back':
            self.session.send_command(tag=PLAYER_BACK)
