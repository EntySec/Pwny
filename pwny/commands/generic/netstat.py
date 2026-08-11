"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

NETSTAT_BASE = 14

NETSTAT_LIST = tlv_custom_tag(API_CALL_STATIC, NETSTAT_BASE, API_CALL)

TLV_TYPE_CONN_PROTO = tlv_custom_type(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE)
TLV_TYPE_CONN_LADDR = tlv_custom_type(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 1)
TLV_TYPE_CONN_RADDR = tlv_custom_type(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 2)
TLV_TYPE_CONN_STATE = tlv_custom_type(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 3)
TLV_TYPE_CONN_LPORT = tlv_custom_type(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE)
TLV_TYPE_CONN_RPORT = tlv_custom_type(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE + 1)
TLV_TYPE_CONN_PID = tlv_custom_type(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE + 2)
TLV_TYPE_CONN_GROUP = tlv_custom_type(TLV_TYPE_GROUP, NETSTAT_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "netstat",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "List active network connections.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--listen'),
                    {
                        'help': "Show only listening sockets.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-t', '--tcp'),
                    {
                        'help': "Show only TCP connections.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-u', '--udp'),
                    {
                        'help': "Show only UDP connections.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-a', '--all'),
                    {
                        'help': "Show all connections (default).",
                        'action': 'store_true',
                    }
                ),
            ]
        })

    def run(self, args):
        result = self.session.send_command(tag=NETSTAT_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to list connections!")
            return

        headers = ('Proto', 'Local Address', 'Remote Address', 'State', 'PID')
        data = []

        while True:
            entry = result.get_tlv(TLV_TYPE_CONN_GROUP)
            if entry is None:
                break

            proto = entry.get_string(TLV_TYPE_CONN_PROTO) or ''
            laddr = entry.get_string(TLV_TYPE_CONN_LADDR) or '*'
            lport = entry.get_int(TLV_TYPE_CONN_LPORT)
            raddr = entry.get_string(TLV_TYPE_CONN_RADDR) or '*'
            rport = entry.get_int(TLV_TYPE_CONN_RPORT)
            state = entry.get_string(TLV_TYPE_CONN_STATE) or ''
            pid = entry.get_int(TLV_TYPE_CONN_PID)

            if args.tcp and proto != 'tcp':
                continue
            if args.udp and proto != 'udp':
                continue
            if args.listen and state != 'LISTEN':
                continue

            local = f"{laddr}:{lport}" if lport else f"{laddr}:*"
            remote = f"{raddr}:{rport}" if rport else f"{raddr}:*"
            pid_str = str(pid) if pid and pid > 0 else '-'

            data.append((proto, local, remote, state, pid_str))

        if not data:
            self.print_warning("No connections found.")
            return

        self.print_table("Connections", headers, *data)
