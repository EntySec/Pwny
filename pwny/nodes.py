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

from hatsploit.lib.session import Session


class Nodes(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny nodes handler implementation.
    """

    def __init__(self) -> None:
        super().__init__()

        self.nodes = {}
        self.nodes_id = 0

    def show_nodes(self) -> None:
        """ Show nodes.

        :return None: None
        """

        headers = ("ID", "Route")
        nodes_data = []

        for node in self.nodes:
            current_node = self.nodes[node]

            src_pair = current_node['src_host'] + ':' + str(current_node['src_port'])
            dst_pair = current_node['dst_host'] + ':' + str(current_node['dst_port'])

            nodes_data.append((src(node), src_pair + ' -> ' + dst_pair))

        self.print_table("Nodes", headers, *nodes_data)

    def add_node(self, src_host: str, src_port: int,
                 dst_host: str, dst_port: int, session: Session) -> None:
        """ Add node.

        :param str src_host: source host
        :param int src_port: source port
        :param str dst_host: destination host
        :param int dst_port: destination port
        :param Session session: session to add node at
        :return None: None
        """

        session.send_command('add_node', args=[
            src_host, str(src_port), dst_host, str(dst_port)],
                             output=False)

        self.nodes[self.nodes_id] = {
            'src_host': src_host,
            'src_port': src_port,
            'dst_host': dst_host,
            'dst_port': dst_port,
        }
        self.nodes_id += 1

    def delete_node(self, node_id: int, session: Session) -> None:
        """ Delete node.

        :param int node_id: node ID
        :param Session session: session to delete node from
        :return None: None
        """

        session.send_command('del_node', args=[str(node_id)], output=False)
        self.nodes.pop(node_id)
