"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import ctypes
import threading

from badges.cmd import Command
from hatsploit.lib.ui.jobs import Job


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "jobs",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage local background jobs.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List all running jobs.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-k', '--kill'),
                    {
                        'help': "Kill running job by ID.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-a', '--add'),
                    {
                        'help': 'Add new background job.',
                        'metavar': 'CMD',
                    }
                )
            ]
        })

        self.jobs = {}

    def job(self, job_id, command):
        self.session.pwny_exec(command)
        self.jobs.pop(job_id)

    def run(self, args):
        if args.list:
            jobs = []

            for job_id, job in self.jobs.items():
                jobs.append((job_id, job['Command']))

            if not jobs:
                self.print_warning("No background jobs running yet.")
                return

            self.print_table('Active Jobs', ('ID', 'Command'), *jobs)

        elif args.kill is not None:
            if args.kill not in self.jobs:
                self.print_error(f"No such job: {str(args.kill)}!")
                return

            self.print_process(f"Killing job {str(args.kill)}...")

            job = self.jobs[args.kill]['Job']
            job.shutdown()
            job.join()

            self.jobs.pop(args.kill)

        elif args.add:
            job_id = 0
            while job_id in self.jobs or \
                    job_id < len(self.jobs):
                job_id += 1

            job = Job(target=self.job, args=(job_id, args.add))
            job.start()

            self.jobs.update({
                job_id: {
                    'Job': job,
                    'Command': args.add
                }
            })
            self.print_information(f"Job {str(job_id)} created.")
