# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

from _br import ffi
from br.c import c2str, mac2str, str2c
from br.cli import Arg, Context


port = Context("port", "Manage ports")


# ------------------------------------------------------------------------------
@port.command(
    Arg("name", help="Port name"),
    Arg("devargs", help="DPDK device arguments"),
)
def port_add(client, parser, args):
    """
    Create a port.
    """
    p = ffi.new("struct br_infra_port *")
    client.infra_port_add(str2c(args.name), str2c(args.devargs), p)
    print_port(p)


# ------------------------------------------------------------------------------
@port.command(
    Arg("name", help="Port name"),
)
def port_del(client, parser, args):
    """
    Delete a port.
    """
    client.infra_port_del(str2c(args.name))


# ------------------------------------------------------------------------------
@port.command(
    Arg("name", help="Port name"),
)
def port_show(client, parser, args):
    """
    Show a port.
    """
    p = ffi.new("struct br_infra_port *")
    client.infra_port_get(str2c(args.name), p)
    print_port(p)


# ------------------------------------------------------------------------------
@port.command()
def port_list(client, parser, args):
    """
    List ports.
    """
    ports = ffi.new("struct br_infra_port []", 32)
    n = ffi.new("size_t *")
    client.infra_port_list(32, ports, n)
    for i in range(n[0]):
        print_port(ports[i])


# ------------------------------------------------------------------------------
def print_port(p):
    print(
        f"""{c2str(p.name)}
    index: {p.index}
    device: {c2str(p.device)}
    mtu: {p.mtu}
    mac: {mac2str(p.mac)}"""
    )
