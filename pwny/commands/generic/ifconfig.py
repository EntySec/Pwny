"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

IFCONFIG_BASE = 13

IFCONFIG_LIST = tlv_custom_tag(API_CALL_STATIC, IFCONFIG_BASE, API_CALL)

TLV_TYPE_IF_NAME = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE)
TLV_TYPE_IF_ADDR = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 1)
TLV_TYPE_IF_MASK = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 2)
TLV_TYPE_IF_BCAST = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 3)
TLV_TYPE_IF_HWADDR = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 4)
TLV_TYPE_IF_ADDR6 = tlv_custom_type(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 5)
TLV_TYPE_IF_FLAGS = tlv_custom_type(TLV_TYPE_INT, IFCONFIG_BASE, API_TYPE)
TLV_TYPE_IF_MTU = tlv_custom_type(TLV_TYPE_INT, IFCONFIG_BASE, API_TYPE + 1)
TLV_TYPE_IF_GROUP = tlv_custom_type(TLV_TYPE_GROUP, IFCONFIG_BASE, API_TYPE)

SIGAR_IFF_UP = 0x1
SIGAR_IFF_BROADCAST = 0x2
SIGAR_IFF_LOOPBACK = 0x8
SIGAR_IFF_POINTOPOINT = 0x10
SIGAR_IFF_RUNNING = 0x40
SIGAR_IFF_PROMISC = 0x100
SIGAR_IFF_MULTICAST = 0x800


def format_flags(flags):
    flag_names = []
    if flags & SIGAR_IFF_UP:
        flag_names.append('UP')
    if flags & SIGAR_IFF_BROADCAST:
        flag_names.append('BROADCAST')
    if flags & SIGAR_IFF_LOOPBACK:
        flag_names.append('LOOPBACK')
    if flags & SIGAR_IFF_POINTOPOINT:
        flag_names.append('POINTOPOINT')
    if flags & SIGAR_IFF_RUNNING:
        flag_names.append('RUNNING')
    if flags & SIGAR_IFF_PROMISC:
        flag_names.append('PROMISC')
    if flags & SIGAR_IFF_MULTICAST:
        flag_names.append('MULTICAST')
    return ','.join(flag_names) if flag_names else str(flags)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "ifconfig",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "List network interfaces and their configuration.",
        })

    def run(self, _):
        result = self.session.send_command(tag=IFCONFIG_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to list network interfaces!")
            return

        count = 0
        while True:
            entry = result.get_tlv(TLV_TYPE_IF_GROUP)
            if entry is None:
                break

            name = entry.get_string(TLV_TYPE_IF_NAME)
            addr = entry.get_string(TLV_TYPE_IF_ADDR)
            mask = entry.get_string(TLV_TYPE_IF_MASK)
            bcast = entry.get_string(TLV_TYPE_IF_BCAST)
            hwaddr = entry.get_string(TLV_TYPE_IF_HWADDR)
            addr6 = entry.get_string(TLV_TYPE_IF_ADDR6)
            flags = entry.get_int(TLV_TYPE_IF_FLAGS) or 0
            mtu = entry.get_int(TLV_TYPE_IF_MTU) or 0

            flag_str = format_flags(flags)

            self.print_information(
                f"{name}: flags={flags:#x}<{flag_str}>  mtu {mtu}"
            )

            if hwaddr and hwaddr != "00:00:00:00:00:00":
                self.print_information(f"        ether {hwaddr}")

            if addr and addr != "0.0.0.0":
                line = f"        inet {addr}"
                if mask:
                    line += f"  netmask {mask}"
                if bcast and bcast != "0.0.0.0":
                    line += f"  broadcast {bcast}"
                self.print_information(line)

            if addr6 and addr6 != "::0" and addr6 != "0:0:0:0:0:0:0:0":
                self.print_information(f"        inet6 {addr6}")

            self.print_empty()
            count += 1

        if count == 0:
            self.print_warning("No network interfaces found.")
