"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "tunnels",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage C2 tunnels.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List all available tunnels.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-c', '--create'),
                    {
                        'help': "Create new tunnel.",
                        'metavar': 'URI'
                    }
                ),
                (
                    ('-t', '--tunnel'),
                    {
                        'help': "Select tunnel to manage.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-s', '--suspend'),
                    {
                        'help': "Suspend specified tunnel.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-a', '--activate'),
                    {
                        'help': 'Activate specified tunnel.',
                        'action': 'store_true'
                    }
                ),
                (
                    ('-k', '--keep-alive'),
                    {
                        'help': "Keep tunnel alive or not when not connected.",
                        'dest': 'alive',
                        'choices': ('on', 'off')
                    }
                ),
                (
                    ('-d', '--delay'),
                    {
                        'help': "Delay for tunnel keep alive.",
                        'type': int
                    }
                )
            ]
        })

    def run(self, args):
        if args.create:
            result = self.session.send_command(
                tag=NET_ADD_TUNNEL,
                args={
                    NET_TYPE_URI: args.create
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to add tunnel: {args.create}!")

            return

        if args.list:
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
            return

        if args.tunnel is None:
            self.print_warning("No tunnel specified.")
            return

        if args.activate:
            self.print_process(f"Activating tunnel {str(args.tunnel)}...")

            self.session.send_command(
                tag=NET_ACTIVATE_TUNNEL,
                args={
                    NET_TYPE_ID: args.tunnel,
                }
            )

        if args.alive:
            delay = args.delay or 10
            self.print_process(f"Toggling keep-alive {args.alive} (delay: {str(delay)}s)...")

            self.session.send_command(
                tag=NET_RESTART_TUNNEL,
                args={
                    NET_TYPE_ID: args.tunnel,
                    NET_TYPE_KEEP_ALIVE: 1 if args.alive == 'on' else 0,
                    NET_TYPE_DELAY: delay
                }
            )

        if args.suspend:
            self.print_process(f"Suspending tunnel {str(args.tunnel)}...")

            result = self.session.send_command(
                tag=NET_SUSPEND_TUNNEL,
                args={
                    NET_TYPE_ID: args.tunnel
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to suspend tunnel {str(args.tunnel)}!")
                return
