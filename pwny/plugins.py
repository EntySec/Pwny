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

from pwny.types import *
from pwny.api import *

from typing import Union
from badges import Tables, Badges

from hatsploit.lib.plugins import Plugins as HatSploitPlugins
from hatsploit.lib.session import Session


class Plugins(Tables, Badges):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    def __init__(self) -> None:
        super().__init__()

        self.plugins = HatSploitPlugins()

        self.imported_plugins = {}
        self.loaded_plugins = {}
        self.plugin_ids = {}

    def import_plugins(self, path: str, session: Session) -> None:
        """ Import plugins for the specified session.

        :param str path: path to import plugins from
        :param Session session: session to import plugins for
        :return None: None
        """

        self.imported_plugins.update(
            self.plugins.import_plugins(path)
        )

        for plugin in self.imported_plugins:
            self.imported_plugins[plugin].session = session

    def show_plugins(self) -> None:
        """ Show plugins.

        :return None: None
        """

        all_plugins = self.imported_plugins
        headers = ("Number", "Name", "Description")

        number = 0
        plugins_data = []

        for plugin in all_plugins:
            plugins_data.append((number, plugin, all_plugins[plugin].details['Description']))
            number += 1

        self.print_table("Plugins", headers, *plugins_data)

    def load_plugin(self, plugin: str) -> Union[int, None]:
        """ Load specified plugin.

        :param str plugin: plugin to load
        :return Union[int, None]: plugin ID if success else None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Loading plugin {plugin}...")

        if plugin not in self.loaded_plugins:
            if plugin in self.imported_plugins:
                plugin_object = self.imported_plugins[plugin]

                session = plugin_object.session
                details = plugin_object.details

                tab_path = (session.pwny_tabs +
                            str(session.details['Platform']) +
                            '/' + str(session.details['Arch']) +
                            '/' + details['Plugin'])

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
            else:
                raise RuntimeError(f"Invalid plugin: {plugin}!")
        else:
            raise RuntimeWarning(f"Plugin is already loaded: {plugin}.")

        self.print_success(f"Loaded plugin {plugin}!")

    def unload_plugin(self, plugin: str) -> None:
        """ Unload specified plugin.

        :param str plugin: plugin to unload
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Unloading plugin {plugin}...")

        if plugin in self.imported_plugins:
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
        else:
            raise RuntimeError(f"Plugin is not loaded: {plugin}!")

        self.print_success(f"Unloaded plugin {plugin}!")
