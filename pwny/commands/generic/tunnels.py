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
            'Category': "manage",
            'Name': "tunnels",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage C2 tunnels.",
            'Usage': "tunnels <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                '-l': ['', 'List available tunnels.'],
                '-c': ['<uri>', 'Create new tunnel.'],
                '-s': ['<id>', 'Suspend existing tunnel.'],
                '-a': ['<id>', 'Activate suspended tunnel.'],
                '-t': ['<id> <delay> [on/off]', 'Toggle keep-alive on tunnel.']
            }
        }

    def run(self, argc, argv):
        if argv[1] == '-c':
            result = self.session.send_command(
                tag=NET_ADD_TUNNEL,
                args={
                    NET_TYPE_URI: argv[2]
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to add tunnel: {argv[2]}!")
                return

        elif argv[1] == '-a':
            self.print_process(f"Activating tunnel {argv[2]}")

            self.session.send_command(
                tag=NET_ACTIVATE_TUNNEL,
                args={
                    NET_TYPE_ID: int(argv[2]),
                }
            )

        elif argv[1] == '-t':
            self.print_process(f"Toggling keep-alive {argv[4].lower()} on {argv[3]}s...")

            self.session.send_command(
                tag=NET_RESTART_TUNNEL,
                args={
                    NET_TYPE_ID: int(argv[2]),
                    NET_TYPE_KEEP_ALIVE: 1 if argv[4].lower() == 'on' else 0,
                    NET_TYPE_DELAY: int(argv[3])
                }
            )

        elif argv[1] == '-s':
            self.print_process(f"Suspending tunnel {argv[2]}...")

            result = self.session.send_command(
                tag=NET_SUSPEND_TUNNEL,
                args={
                    NET_TYPE_ID: int(argv[2])
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to suspend tunnel {argv[1]}!")
                return

        elif argv[1] == '-l':
            result = self.session.send_command(
                tag=NET_TUNNELS)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to retrieve tunnels!")
                return

            data = []
            headers = ('Self', 'ID', 'URI', 'Encryption', 'Status', 'Delay', 'Keep-Alive')
            tunnel = result.get_tlv(TLV_TYPE_GROUP)

            while tunnel:
                asterisk = '*' if tunnel.get_int(TLV_TYPE_BOOL) else ''
                status = 'active' if tunnel.get_int(TLV_TYPE_INT) else 'suspended'
                keep_alive = 'on' if tunnel.get_int(NET_TYPE_KEEP_ALIVE) else 'off'

                data.append(
                    (asterisk, tunnel.get_int(NET_TYPE_ID),
                     tunnel.get_string(NET_TYPE_URI),
                     ALGO[tunnel.get_int(NET_TYPE_ALGO)], status,
                     f'{str(tunnel.get_int(NET_TYPE_DELAY))}s',
                     keep_alive))
                tunnel = result.get_tlv(TLV_TYPE_GROUP)

            self.print_table('Tunnels', headers, *data)
