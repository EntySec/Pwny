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

import os

from pwny.api import *
from pwny.types import *

from typing import Union
from badges import Badges

from hatsploit.core.db.importer import Importer
from hatsploit.lib.core.session import Session
from hatsploit.lib.ui.show import Show


class Plugins(Badges):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    def __init__(self) -> None:
        self.imported_plugins = {}
        self.loaded_plugins = {}
        self.plugin_ids = {}

    def import_plugins(self, path: str, session: Session) -> None:
        """ Import plugins for the specified session.

        :param str path: path to import plugins from
        :param Session session: session to import plugins for
        :return None: None
        """

        for file in os.listdir(path):
            if not file.endswith('.py') or file == '__init__.py':
                continue

            plugin = Importer.import_plugin(path + '/' + file)
            plugin.session = session
            plugin_name = plugin.info['Plugin']

            self.imported_plugins[plugin_name] = plugin

    def show_plugins(self) -> None:
        """ Show plugins.

        :return None: None
        """

        Show().show_loaded_plugins(self.imported_plugins)

    def load_plugin(self, plugin: str) -> None:
        """ Load specified plugin.

        :param str plugin: plugin to load
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Loading plugin {plugin}...")

        if plugin in self.loaded_plugins:
            raise RuntimeWarning(f"Plugin is already loaded: {plugin}.")

        if plugin not in self.imported_plugins:
            raise RuntimeError(f"Invalid plugin: {plugin}!")

        plugin_object = self.imported_plugins[plugin]

        session = plugin_object.session
        info = plugin_object.info

        tab_path = (session.pwny_tabs +
                    str(session.info['Platform']) +
                    '/' + str(session.info['Arch']) +
                    '/' + info['Plugin'])

        if os.path.exists(tab_path):
            with open(tab_path, 'rb') as f:
                data = f.read()

                tlv = session.send_command(
                    tag=BUILTIN_ADD_TAB_BUFFER,
                    args={
                        TLV_TYPE_TAB: data
                    }
                )

                if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                    raise RuntimeError(f"Failed to load plugin: {plugin}!")

                tab_id = tlv.get_int(TLV_TYPE_TAB_ID)
                plugin_object.plugin = tab_id
                self.plugin_ids[plugin] = tab_id

        else:
            self.print_warning("No TAB was sent to a client.")
            self.plugin_ids[plugin] = -len(self.loaded_plugins)

        self.loaded_plugins[plugin] = plugin_object
        plugin_object.load()

        self.print_success(f"Loaded plugin {plugin}!")

    def unload_plugin(self, plugin: str) -> None:
        """ Unload specified plugin.

        :param str plugin: plugin to unload
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Unloading plugin {plugin}...")

        if plugin not in self.imported_plugins:
            raise RuntimeError(f"Plugin is not loaded: {plugin}!")

        plugin_object = self.loaded_plugins[plugin]
        session = plugin_object.session

        if self.plugin_ids[plugin] >= 0:
            tlv = session.send_command(
                tag=TAB_TERM,
                args={
                    TLV_TYPE_TAB_ID: self.plugin_ids[plugin]
                }
            )

            if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_QUIT:
                raise RuntimeError(f"Failed to quit plugin: {plugin}!")

            tlv = session.send_command(
                tag=BUILTIN_DEL_TAB,
                args={
                    TLV_TYPE_INT: self.plugin_ids[plugin]
                }
            )

            if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                raise RuntimeError(f"Failed to unload plugin: {plugin}!")

        self.loaded_plugins.pop(plugin)
        self.plugin_ids.pop(plugin)

        self.print_success(f"Unloaded plugin {plugin}!")
