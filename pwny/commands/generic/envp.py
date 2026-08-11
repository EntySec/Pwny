"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

ENV_BASE = 18

ENV_LIST = tlv_custom_tag(API_CALL_STATIC, ENV_BASE, API_CALL)
ENV_GET = tlv_custom_tag(API_CALL_STATIC, ENV_BASE, API_CALL + 1)
ENV_SET = tlv_custom_tag(API_CALL_STATIC, ENV_BASE, API_CALL + 2)
ENV_UNSET = tlv_custom_tag(API_CALL_STATIC, ENV_BASE, API_CALL + 3)

TLV_TYPE_ENV_KEY = tlv_custom_type(TLV_TYPE_STRING, ENV_BASE, API_TYPE)
TLV_TYPE_ENV_VALUE = tlv_custom_type(TLV_TYPE_STRING, ENV_BASE, API_TYPE + 1)
TLV_TYPE_ENV_GROUP = tlv_custom_type(TLV_TYPE_GROUP, ENV_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "envp",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "View, get, set, or unset environment variables.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List all environment variables.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-g', '--get'),
                    {
                        'help': "Get value of an environment variable.",
                        'metavar': 'NAME',
                    }
                ),
                (
                    ('-s', '--set'),
                    {
                        'help': "Set environment variable NAME=VALUE.",
                        'metavar': 'NAME',
                    }
                ),
                (
                    ('-v', '--value'),
                    {
                        'help': "Value for --set.",
                        'metavar': 'VALUE',
                    }
                ),
                (
                    ('-u', '--unset'),
                    {
                        'help': "Unset an environment variable.",
                        'metavar': 'NAME',
                    }
                ),
            ]
        })

    def run(self, args):
        if args.list:
            result = self.session.send_command(tag=ENV_LIST)

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to list environment variables!")
                return

            count = 0
            while True:
                entry = result.get_tlv(TLV_TYPE_ENV_GROUP)
                if entry is None:
                    break
                key = entry.get_string(TLV_TYPE_ENV_KEY)
                value = entry.get_string(TLV_TYPE_ENV_VALUE)
                self.print_information(f"{key}={value}")
                count += 1

            if count == 0:
                self.print_warning("No environment variables found.")

        elif args.get:
            result = self.session.send_command(
                tag=ENV_GET,
                args={
                    TLV_TYPE_ENV_KEY: args.get,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Environment variable '{args.get}' not found!")
                return

            value = result.get_string(TLV_TYPE_ENV_VALUE)
            self.print_information(f"{args.get}={value}")

        elif args.set:
            if args.value is None:
                self.print_error("Specify value with --value!")
                return

            result = self.session.send_command(
                tag=ENV_SET,
                args={
                    TLV_TYPE_ENV_KEY: args.set,
                    TLV_TYPE_ENV_VALUE: args.value,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to set environment variable!")
                return

            self.print_success(f"Set {args.set}={args.value}")

        elif args.unset:
            result = self.session.send_command(
                tag=ENV_UNSET,
                args={
                    TLV_TYPE_ENV_KEY: args.unset,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to unset environment variable!")
                return

            self.print_success(f"Unset {args.unset}")

        else:
            self.print_usage()
