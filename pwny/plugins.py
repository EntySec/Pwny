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

from hatsploit.core.db.importer import Importer


class Plugins:
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    importer = Importer()

    def load_plugins(self, path):
        if not path.endswith('/'):
            path += '/'

        plugins = {}
        plugin_path = os.path.split(path)[0]

        for file in os.listdir(plugin_path):
            if file.endswith('py'):
                try:
                    plugin_object = self.plugins.import_plugin(plugin_path + '/' + file[:-3])
                    plugin_name = plugin_object.details['Name']
                    plugins[plugin_name] = plugin_object
                except Exception:
                    self.badges.print_error(f"Failed to load {file[:-3]} plugin!")

        return plugins
