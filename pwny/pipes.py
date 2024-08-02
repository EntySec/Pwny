"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import threading
from random import randint

from typing import (
    Optional,
    Callable,
    Any,
)
from pwny.api import *

from hatsploit.lib.core.session import Session


class Pipes(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    pipes client.
    """

    def __init__(self, session: Session) -> None:
        """ Initialize pipes client.

        :param Session session: session
        :return None: None
        """

        self.session = session

        self.events = {}
        self.plugin_events = {}

        self.pipes = {}
        self.plugin_pipes = {}

        self.running = False

    def has_events(self) -> bool:
        """ Check if there are any events running.

        :return bool: True if any events running
        """

        return self.events or self.plugin_events

    def interrupt_events(self) -> None:
        """ Interrupt all events.

        :return None: None
        """

        self.running = False

    def resume_events(self) -> None:
        """ Resume all events.

        :return None: None
        """

        self.running = True

        for pipe_type in self.events:
            events = self.events[pipe_type]

            for pipe_id in events:
                self.resume_pipe_events(pipe_type, pipe_id)

        for plugin in self.plugin_events:
            for pipe_type in self.plugin_events[plugin]:
                events = self.plugin_events[plugin][pipe_type]

                for pipe_id in events:
                    self.resume_pipe_events(pipe_type, pipe_id, plugin)

    def resume_pipe_events(self, pipe_type: int, pipe_id: int,
                           plugin: Optional[int] = None) -> None:
        """ Resume single event.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        """

        self.check_pipe(pipe_type, pipe_id, plugin)
        events = self.events

        if plugin is not None:
            events = self.plugin_events[plugin]

        events = events[pipe_type][pipe_id]

        for event in events:
            thread = threading.Thread(
                target=self.event_thread,
                args=events[event]['Args']
            )
            thread.setDaemon(True)

            events[event]['Thread'] = thread
            events[event]['Flush'] = False

            thread.start()

    def create_event(self, pipe_type: int, pipe_id: int, pipe_data: int,
                     target: Callable[..., Any], args: list = [],
                     plugin: Optional[int] = None) -> None:
        """ Create event on a pipe (wait for event).

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int pipe_data: type of data you expect to receive
        :param Callable[..., Any] target: function to execute on event
        :param list args: function args
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        """

        self.check_pipe(pipe_type, pipe_id, plugin)
        events = self.events

        if plugin is not None:
            if plugin not in self.plugin_events:
                self.plugin_events[plugin] = {}

            events = self.plugin_events[plugin]

        if pipe_type not in events:
            events[pipe_type] = {}

        if pipe_id not in events:
            events[pipe_type][pipe_id] = {}

        event_id = randint(100000, 999999)
        events = events[pipe_type][pipe_id]

        event_args = [
            event_id,
            pipe_type,
            pipe_id,
            pipe_data,
            target,
            args,
            plugin
        ]

        thread = threading.Thread(
            target=self.event_thread,
            args=event_args
        )
        thread.setDaemon(True)

        events[event_id] = {
            'Thread': thread,
            'Flush': False,
            'Args': event_args
        }

        self.running = True
        thread.start()

    def event_thread(self, event_id: int, pipe_type: int,
                     pipe_id: int, pipe_data: int,
                     target: Callable[..., Any], args: list = [],
                     plugin: Optional[int] = None) -> None:
        """ Event thread.

        :param int event_id: pipe event ID
        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int pipe_data: type of data you expect to receive
        :param Callable[..., Any] target: function to execute on read
        :param list args: function args
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        """

        self.check_pipe(pipe_type, pipe_id, plugin)
        events = self.events

        if plugin is not None:
            events = self.plugin_events[plugin]

        events = events[pipe_type][pipe_id]
        event = events[event_id]

        while not event['Flush'] and self.running:
            query = {
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id
            }

            result = None

            while result is None:
                if event['Flush']:
                    return

                result = self.session.channel.queue_find(
                    args=query,
                    delete=False
                )

                if result is None:
                    continue

                if result.get_int(TLV_TYPE_TAG, delete=False):
                    result = None
                    continue

                if not result.get_raw(pipe_data, delete=False):
                    result = None
                    continue

            self.session.channel.queue_delete(result)

            if target:
                target(result, *args)

    def check_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> None:
        """ Check if pipe exists.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        pipes = self.pipes

        if plugin is not None:
            if plugin not in self.plugin_pipes:
                raise RuntimeError(f"Plugin has no pipe with ID #{str(pipe_id)}!")

            pipes = self.plugin_pipes[plugin]

        if pipe_type not in pipes:
            raise RuntimeError(f"Pipe {str(pipe_id)} type and ID mismatch!")

        if pipe_id not in pipes[pipe_type]:
            raise RuntimeError(f"No such pipe with ID {str(pipe_id)}!")

    def heartbeat_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> bool:
        """ Check pipe is alive or not.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return bool: True if alive else False
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_HEARTBEAT,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
            },
            plugin=plugin
        )

        if tlv.get_int(PIPE_TYPE_HEARTBEAT) == TLV_STATUS_FAIL:
            return False

        return True

    def tell_pipe(self, pipe_type: int, pipe_id: int, plugin: Optional[int] = None) -> int:
        """ Tell from pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return int: offset
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_TELL,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to tell from pipe {str(pipe_id)}!")

        return tlv.get_int(PIPE_TYPE_OFFSET)

    def seek_pipe(self, pipe_type: int, pipe_id: int,
                  offset: int, whence: int, plugin: Optional[int] = None) -> None:
        """ Seek in the pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int offset: offset
        :param int whence: whence
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_SEEK,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_OFFSET: offset,
                PIPE_TYPE_WHENCE: whence,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to seek in pipe {str(pipe_id)}!")

    def write_pipe(self, pipe_type: int, pipe_id: int, buffer: bytes,
                   plugin: Optional[int] = None) -> None:
        """ Write stream to pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param bytes buffer: buffer to write
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_WRITE,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_LENGTH: len(buffer),
                PIPE_TYPE_BUFFER: buffer,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to write to pipe {str(pipe_id)}!")

    def read_pipe(self, pipe_type: int, pipe_id: int, size: int,
                  plugin: Optional[int] = None) -> bytes:
        """ Read stream from pipe.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param int size: count of bytes to read
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return bytes: bytes
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        tlv = self.session.send_command(
            tag=PIPE_READ,
            args={
                PIPE_TYPE_TYPE: pipe_type,
                PIPE_TYPE_ID: pipe_id,
                PIPE_TYPE_LENGTH: size,
            },
            plugin=plugin
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to read from pipe {str(pipe_id)}!")

        return tlv.get_raw(PIPE_TYPE_BUFFER)

    def create_pipe(self, pipe_type: int, args: dict = {},
                    flags: Optional[int] = 0,
                    plugin: Optional[int] = None) -> int:
        """ Create new pipe of type.

        :param int pipe_type: type of pipe
        :param dict args: additional args
        :param Optional[int] flags: additional flags
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return int: pipe ID
        :raises RuntimeError: with trailing error message
        """

        pipes = self.pipes

        if plugin is not None:
            if plugin not in self.plugin_pipes:
                self.plugin_pipes[plugin] = {}

            pipes = self.plugin_pipes[plugin]

        if pipe_type not in pipes:
            pipes[pipe_type] = {}

        pipe_id = randint(100000, 999999)

        args.update({
            PIPE_TYPE_TYPE: pipe_type,
            PIPE_TYPE_ID: pipe_id,
            PIPE_TYPE_FLAGS: flags,
        })

        tlv = self.session.send_command(
            tag=PIPE_CREATE,
            args=args
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to create pipe {str(pipe_id)}!")

        pipes[pipe_type][pipe_id] = {}
        return pipe_id

    def destroy_pipe(self, pipe_type: int, pipe_id: int, args: dict = {},
                     plugin: Optional[int] = None) -> None:
        """ Destroy pipe of type by ID.

        :param int pipe_type: type of pipe
        :param int pipe_id: pipe ID
        :param dict args: additional args
        :param Optional[int] plugin: plugin ID if refer to plugin
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.check_pipe(pipe_type, pipe_id, plugin)

        pipes = self.pipes
        events = self.events

        if plugin is not None:
            pipes = self.plugin_pipes.get(plugin, pipes)
            events = self.plugin_events.get(plugin, events)

        if pipe_type in events:
            pipe_events = events[pipe_type].get(pipe_id, {})

            for event in pipe_events:
                pipe_events[event]['Flush'] = True
                pipe_events[event]['Thread'].join()

            if pipe_id in events[pipe_type]:
                events[pipe_type].pop(pipe_id)

        args.update({
            PIPE_TYPE_TYPE: pipe_type,
            PIPE_TYPE_ID: pipe_id
        })

        tlv = self.session.send_command(
            tag=PIPE_DESTROY,
            args=args
        )

        if tlv.get_int(TLV_TYPE_STATUS) == TLV_STATUS_FAIL:
            raise RuntimeError(f"Failed to destroy pipe {str(pipe_id)}!")

        pipes[pipe_type].pop(pipe_id)
