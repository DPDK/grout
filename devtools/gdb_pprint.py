# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

import socket

import gdb
import gdb.printing


class IP4Address:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        buf = self.val.address.cast(gdb.lookup_type("unsigned char").pointer())
        return socket.inet_ntop(socket.AF_INET, bytes(buf[i] for i in range(4)))


class IP6Address:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        buf = bytes(self.val["a"][i] for i in range(16))
        return socket.inet_ntop(socket.AF_INET6, buf)


class EtherAddress:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        buf = bytes(self.val["addr_bytes"][i] for i in range(6))
        return ":".join(f"{b:02x}" for b in buf)


class Iface:
    TYPE_STRUCTS = {
        "GR_IFACE_TYPE_PORT": "struct __gr_iface_info_port_base",
        "GR_IFACE_TYPE_VLAN": "struct gr_iface_info_vlan",
        "GR_IFACE_TYPE_IPIP": "struct gr_iface_info_ipip",
    }

    def __init__(self, val):
        self.val = val
        self.sub_types = {}
        for type_id, struct in self.TYPE_STRUCTS.items():
            type_id = int(gdb.lookup_static_symbol(type_id).value())
            struct = gdb.lookup_type(struct)
            self.sub_types[type_id] = struct

    def children(self):
        base_type = gdb.lookup_type("struct __gr_iface_base")
        ptr = self.val.address.cast(base_type.pointer())
        base = ptr.dereference()
        yield (("base", base))

        for field in self.val.type.strip_typedefs().fields():
            if field.name is None:
                continue

            if field.name == "info" and int(self.val["type"]) in self.sub_types:
                port_type = self.sub_types[int(self.val["type"])]
                ptr = self.val["info"].address.cast(port_type.pointer())
                info = ptr.dereference()
                yield (("info", info))
            else:
                # yield normally → GDB prints colored "field = value"
                yield (field.name, self.val[field])


def load_grout_pprint():
    pp = gdb.printing.RegexpCollectionPrettyPrinter("grout")
    pp.add_printer("ip4_addr_t", r"^ip4_addr_t$", IP4Address)
    pp.add_printer("struct rte_ipv6_addr", r"^rte_ipv6_addr$", IP6Address)
    pp.add_printer("struct rte_ether_addr", r"^rte_ether_addr$", EtherAddress)
    pp.add_printer("struct iface", r"^iface$", Iface)
    return pp


gdb.printing.register_pretty_printer(
    gdb.current_objfile(), load_grout_pprint(), replace=True
)
