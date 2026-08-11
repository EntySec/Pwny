"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import time
import datetime
import threading
import string

from pwny.api import *
from pwny.types import *

from pex.string import String
from badges.cmd import Command


class ExternalCommand(Command, String):
    def __init__(self):
        super().__init__({
            'Category': "filesystem",
            'Name': "find",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Search for file or directory.",
            'MinArgs': 1,
            'Options': [
                (
                    ('keyword',),
                    {
                        'help': 'Keyword to search for.',
                    }
                ),
                (
                    ('-p', '--path'),
                    {
                        'help': 'Path where to search for (default: .)',
                        'dest': 'path',
                        'required': False
                    }
                ),
                (
                    ('-r', '--recursive'),
                    {
                        'help': 'Perform recursive search.',
                        'action': 'store_true',
                        'required': False,
                    }
                ),
                (
                    ('-s', '--start-date'),
                    {
                        'help': 'Start date (format: YY-MM-DD)',
                        'dest': 'start_date',
                        'required': False
                    }
                ),
                (
                    ('-e', '--end-date'),
                    {
                        'help': 'End date (format: YY-MM-DD)',
                        'dest': 'end_date',
                        'required': False
                    }
                )
            ]
        })

        self.result = None
        self.thread = None

    def wait(self):
        base_line = "Searching for results... "
        cycle = 0

        while self.thread.is_alive():
            for char in r"/-\|":
                status = base_line + char
                cycle += 1

                self.print_process(status, '', '\r')
                time.sleep(0.1)

        self.print_empty('\r' + ' ' * (len(base_line) + 5), end='')
        self.thread.join()

    def search(self, args):
        self.result = self.session.send_command(
            tag=FS_FIND,
            args=args
        )

    def run(self, args):
        result = self.session.send_command(tag=FS_GETWD)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to get current working directory!")
            return

        current = result.get_string(TLV_TYPE_PATH)
        sess_args = {
            TLV_TYPE_FILENAME: args.keyword,
            TLV_TYPE_INT: args.recursive,
            TLV_TYPE_PATH: current,
        }

        if args.path:
            sess_args.update({
                TLV_TYPE_PATH: args.path
            })

        if args.start_date:
            try:
                sess_args.update({
                    FS_TYPE_START_DATE: int(
                        datetime.datetime.strptime(
                            args.start_date, "%Y-%m-%d").timestamp())
                })

            except ValueError:
                self.print_error("Incorrect start date format, should be YY-MM-DD!")
                self.print_warning("Skipping provided start date.")

        if args.end_date:
            try:
                sess_args.update({
                    FS_TYPE_END_DATE: int(
                        datetime.datetime.strptime(
                            args.end_date, "%Y-%m-%d").timestamp())
                })

            except ValueError:
                self.print_error("Incorrect end date format, should be YY-MM-DD!")
                self.print_warning("Skipping provided end date.")

        self.thread = threading.Thread(
            target=self.search, args=(sess_args,))
        self.thread.setDaemon(True)
        self.thread.start()

        self.wait()

        if self.result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Remote file: {args.keyword}: does not exist!")
            return

        stat = self.result.get_tlv(TLV_TYPE_GROUP)
        headers = ('Mode', 'Size', 'Type', 'Modified', 'Name')
        data = []

        while stat:
            buffer = stat.get_raw(TLV_TYPE_BYTES)
            try:
                hash = self.bytes_to_stat(buffer)
            except Exception:
                hash = {}

            file_size = self.size_normalize(hash.get('st_size', 0))
            file_mode = self.mode_symbolic(hash.get('st_mode', 0))
            file_type = self.mode_type(hash.get('st_mode', 0))
            file_time = self.time_normalize(hash.get('st_mtime', 0))
            file_name = stat.get_string(TLV_TYPE_FILENAME)

            file_path = stat.get_string(TLV_TYPE_PATH)

            if file_path == current:
                file_path = '.'

            data.append((file_mode, file_size, file_type,
                         file_time, os.path.join(file_path, file_name)))
            stat = self.result.get_tlv(TLV_TYPE_GROUP)

        self.print_table(f'Results', headers, *sorted(data))
