"""
MIT License

Copyright (c) 2020-2026 EntySec

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

import os
import json
import shutil
import pathlib

from typing import Optional, Union

from pwny.https import generate_self_signed, extract_pin


class CertHive(object):
    """ Certificate hive for managing named TLS certificates.

    Stores certificates under ~/.pwny/certs/<name>/ with a
    metadata JSON file for each entry.
    """

    def __init__(self, path: str = '') -> None:
        if not path:
            path = os.path.join(str(pathlib.Path.home()), '.pwny', 'certs')

        self.path = path
        os.makedirs(self.path, exist_ok=True)

    def _entry_dir(self, name: str) -> str:
        return os.path.join(self.path, name)

    def _meta_path(self, name: str) -> str:
        return os.path.join(self._entry_dir(name), 'meta.json')

    def _key_path(self, name: str) -> str:
        return os.path.join(self._entry_dir(name), 'server.key')

    def _cert_path(self, name: str) -> str:
        return os.path.join(self._entry_dir(name), 'server.crt')

    def exists(self, name: str) -> bool:
        """ Check if a named certificate exists.

        :param str name: certificate name
        :return bool: True if exists
        """

        return os.path.isdir(self._entry_dir(name))

    def generate(self, name: str) -> dict:
        """ Generate a new named certificate.

        :param str name: certificate name
        :return dict: entry metadata including pin
        :raises FileExistsError: if name already exists
        """

        if self.exists(name):
            raise FileExistsError(f"Certificate '{name}' already exists")

        entry_dir = self._entry_dir(name)
        os.makedirs(entry_dir)

        keyfile = self._key_path(name)
        certfile = self._cert_path(name)

        generate_self_signed(keyfile, certfile)
        pin = extract_pin(certfile)

        meta = {
            'name': name,
            'pin': pin,
            'keyfile': keyfile,
            'certfile': certfile,
        }

        with open(self._meta_path(name), 'w') as f:
            json.dump(meta, f, indent=2)

        return meta

    def get(self, name: str) -> dict:
        """ Get metadata for a named certificate.

        :param str name: certificate name
        :return dict: entry metadata
        :raises FileNotFoundError: if name does not exist
        """

        if not self.exists(name):
            raise FileNotFoundError(f"Certificate '{name}' not found")

        with open(self._meta_path(name)) as f:
            return json.load(f)

    def list(self) -> list:
        """ List all certificate entries.

        :return list: list of metadata dicts
        """

        entries = []

        for name in sorted(os.listdir(self.path)):
            meta_path = self._meta_path(name)

            if os.path.isfile(meta_path):
                with open(meta_path) as f:
                    entries.append(json.load(f))

        return entries

    def delete(self, name: str) -> None:
        """ Delete a named certificate.

        :param str name: certificate name
        :raises FileNotFoundError: if name does not exist
        """

        if not self.exists(name):
            raise FileNotFoundError(f"Certificate '{name}' not found")

        shutil.rmtree(self._entry_dir(name))

    def rename(self, old_name: str, new_name: str) -> dict:
        """ Rename a certificate entry.

        :param str old_name: current name
        :param str new_name: new name
        :return dict: updated metadata
        :raises FileNotFoundError: if old_name does not exist
        :raises FileExistsError: if new_name already exists
        """

        if not self.exists(old_name):
            raise FileNotFoundError(f"Certificate '{old_name}' not found")

        if self.exists(new_name):
            raise FileExistsError(f"Certificate '{new_name}' already exists")

        old_dir = self._entry_dir(old_name)
        new_dir = self._entry_dir(new_name)

        os.rename(old_dir, new_dir)

        meta = self.get(new_name)
        meta['name'] = new_name
        meta['keyfile'] = self._key_path(new_name)
        meta['certfile'] = self._cert_path(new_name)

        with open(self._meta_path(new_name), 'w') as f:
            json.dump(meta, f, indent=2)

        return meta
