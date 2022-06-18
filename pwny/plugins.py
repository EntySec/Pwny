"""
MIT License

Copyright (c) 2020-2022 EntySec

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

from hatsploit.lib.plugins import Plugins
from hatsploit.lib.session import Session


class Plugins:
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    plugins = Plugins()

    imported_plugins = {}
    loaded_plugins = {}

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

    def load_plugin(self, plugin: str) -> None:
        """ Load specified plugin.

        :param str plugin: plugin to load
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if plugin not in self.loaded_plugins:
            if plugin in self.imported_plugins:
                self.loaded_plugins.update({plugin: self.imported_plugins[plugin]})
                self.imported_plugins[plugin].load()
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
            self.loaded_plugins.pop(plugin)
        else:
            raise RuntimeError(f"Plugin is not loaded: {plugin}!")
