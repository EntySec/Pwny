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

from pex.socket import Socket

from pwny.types import *
from pwny.api import *

from hatsploit.lib.session import Session


class Nodes(object):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny nodes handler implementation.
    """

    def __init__(self) -> None:
        super().__init__()

        self.nodes = {}

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

            nodes_data.append((str(node), src_pair + ' -> ' + dst_pair))

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
        :raises RuntimeError: with trailing error message
        """

        tlv = session.send_command(
            tag=BUILTIN_ADD_NODE,
            args={
                TLV_TYPE_NODE_SRC_ADDR: int.from_bytes(Socket().pack_host(src_host), 'little'),
                TLV_TYPE_NODE_DST_ADDR: int.from_bytes(Socket().pack_host(dst_host), 'little'),
                TLV_TYPE_NODE_SRC_PORT: int.from_bytes(Socket().pack_port(src_port), 'little'),
                TLV_TYPE_NODE_DST_PORT: int.from_bytes(Socket().pack_port(dst_port), 'little')
            }
        )

        if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError("Failed to add the specified node!")

        node_id = tlv.get_int(TLV_TYPE_NODE_ID)

        self.nodes[node_id] = {
            'src_host': src_host,
            'src_port': src_port,
            'dst_host': dst_host,
            'dst_port': dst_port,
        }

    def delete_node(self, node_id: int, session: Session) -> None:
        """ Delete node.

        :param int node_id: node ID
        :param Session session: session to delete node from
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if node_id in self.nodes:
            tlv = session.send_command(
                tag=BUILTIN_DEL_NODE,
                args={
                    TLV_TYPE_NODE_ID: node_id
                }
            )

            if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                raise RuntimeError(f"Failed to delete node #{str(node_id)}!")

            self.nodes.pop(node_id)

        else:
            raise RuntimeError(f"Node #{str(node_id)} does not exist!")
