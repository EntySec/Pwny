"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command

PLAYER_BASE = 7

PLAYER_INFO = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL)
PLAYER_PLAY = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 1)
PLAYER_PAUSE = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 2)
PLAYER_NEXT = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 3)
PLAYER_BACK = tlv_custom_tag(API_CALL_STATIC, PLAYER_BASE, API_CALL + 4)

PLAYER_TITLE = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE)
PLAYER_ALBUM = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE + 1)
PLAYER_ARTIST = tlv_custom_type(TLV_TYPE_STRING, PLAYER_BASE, API_TYPE + 2)


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "UI",
            'Name': "player",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Manipulate MediaPlayer.",
            'Usage': "player <option>",
            'MinArgs': 1,
            'Options': {
                'info': ['', 'Get current playing song.'],
                'play': ['', 'Play the current song.'],
                'pause': ['', 'Pause the current song.'],
                'next': ['', 'Play next song.'],
                'back': ['', 'Play previous song.']
            }
        }

    def run(self, argc, argv):
        if argv[1] == 'info':
            result = self.session.send_command(tag=PLAYER_INFO)

            self.print_information(f"Title:  {result.get_string(PLAYER_TITLE)}")
            self.print_information(f"Album:  {result.get_string(PLAYER_ALBUM)}")
            self.print_information(f"Artist: {result.get_string(PLAYER_ARTIST)}")

        elif argv[1] == 'play':
            self.session.send_command(tag=PLAYER_PLAY)

        elif argv[1] == 'pause':
            self.session.send_command(tag=PLAYER_PAUSE)

        elif argv[1] == 'next':
            self.session.send_command(tag=PLAYER_NEXT)

        elif argv[1] == 'back':
            self.session.send_command(tag=PLAYER_BACK)
