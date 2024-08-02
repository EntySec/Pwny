"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import ctypes
import threading

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "jobs",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage local background jobs.",
            'Usage': "jobs <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                'list': ['', 'List running jobs.'],
                'kill': ['<id>', 'Kill running job.'],
                'add': ['<commands>', 'Create background job.']
            }
        })

        self.jobs = {}

    def job(self, job_id, command):
        self.session.pwny_exec(command)
        self.jobs.pop(job_id)

    def run(self, args):
        if args[1] == 'list':
            jobs = []

            for job_id, job in self.jobs.items():
                jobs.append((job_id, job['Command']))

            if not jobs:
                self.print_warning("No background jobs running yet.")
                return

            self.print_table('Active Jobs', ('ID', 'Command'), *jobs)

        elif args[1] == 'delete':
            if int(args[2]) not in self.jobs:
                self.print_error(f"No such job: {args[2]}!")
                return

            self.print_process(f"Killing job {args[2]}...")

            job = self.jobs[int(args[2])]
            thread = job['Thread']

            if thread.is_alive():
                exc = ctypes.py_object(SystemExit)
                res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread.ident), exc)

                if res > 1:
                    ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)

            self.jobs.pop(int(args[2]))

        elif args[1] == 'add':
            command = ' '.join(args[2:])
            job_id = len(self.jobs)

            thread = threading.Thread(target=self.job, args=(job_id, command))
            thread.setDaemon(True)

            self.jobs[len(self.jobs)] = {
                'Thread': thread,
                'Command': command
            }

            thread.start()
            self.print_information("Job created.")
