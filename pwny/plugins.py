"""
MIT License

Copyright (c) 2020-2023 EntySec

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

from badges import Tables

from hatsploit.lib.plugins import Plugins as HatSploitPlugins
from hatsploit.lib.session import Session


class Plugins(Tables):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    def __init__(self) -> None:
        super().__init__()

        self.plugins = HatSploitPlugins()

        self.imported_plugins = {}
        self.loaded_plugins = {}

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

    def load_plugin(self, plugin: str) -> None:
        """ Load specified plugin.

        :param str plugin: plugin to load
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if plugin not in self.loaded_plugins:
            if plugin in self.imported_plugins:
                plugin_object = self.imported_plugins[plugin]
                self.loaded_plugins.update({plugin: plugin_object})

                session = self.imported_plugins[plugin].session
                details = plugin_object.details

                tab_path = (session.pwny_libs +
                            session.details['Platform'] +
                            '/' + session.details['Architecture'] +
                            '/' + details['Plugin'])

                if os.path.exists(tab_path):
                    with open(tab_path, 'rb') as f:
                        data = f.read()

                        session.send_command('add_tab', args=[
                            details['Pool'].to_bytes(4, 'little'), data])

                    plugin_object.load()
                else:
                    self.loaded_plugins.pop(plugin)
                    raise RuntimeError(f"Plugin executable link does not exist at {tab_path}!")
            else:
                raise RuntimeError(f"Invalid plugin: {plugin}!")
        else:
            raise RuntimeWarning(f"Plugin is already loaded: {plugin}.")

    def unload_plugin(self, plugin: str) -> None:
        """ Unload specified plugin.

        :param str plugin: plugin to unload
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if plugin in self.imported_plugins:
            plugin_object = self.loaded_plugins[plugin]

            plugin_object.session.send_command('del_tab', args=[str(
                plugin_object.details['Pool']
            )], output=False)

            self.loaded_plugins.pop(plugin)
        else:
            raise RuntimeError(f"Plugin is not loaded: {plugin}!")
