#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Abhiram R N

"""
Parse grcli --dump and generate man pages in the scdoc format.
"""

import argparse
import dataclasses
import json
import sys


@dataclasses.dataclass
class Node:
    type: str
    desc: str
    has_cb: bool
    id: str
    help: str
    children: list["Node"]


def print_header(name: str, description: str):
    print(f"{name.upper()}(1)")
    print()
    print("# NAME")
    print()
    print(f"{name} - {description}")
    print()
    print("# SYNOPSIS")


def print_trailer(see_also: list[str]):
    print()
    print("# SEE ALSO")
    print()
    for man in sorted(see_also):
        print(man)
    print()
    print("# REPORTING BUGS")
    print()
    print("Report bugs to the grout project issue tracker at")
    print("<https://github.com/DPDK/grout/issues>.")


def print_flag(node: Node, short: bool):
    flags = []
    if node.children[0].type == "seq":
        node = node.children[0]
    for child in node.children:
        if child.type == "or":
            for c in child.children:
                flags.append(f"*{c.desc}*")
        else:
            for i in range(len(flags)):
                flags[i] += f" _{child.desc}_"
    if short:
        print(flags[0], end="")
    else:
        print(", ".join(flags), end="")


def print_main_page(tree: Node):
    print_header("grcli", "grout command line interface")

    print()
    print("*grcli*")
    for opt in tree.children[1].children[0].children:
        print(r"\[", end="")
        print_flag(opt, True)
        print("]")

    print()
    print("# OPTIONS")
    for opt in tree.children[1].children[0].children:
        print()
        print_flag(opt, False)
        print()
        print(f"\t{opt.help}")

    print()
    print("# ENVIRONMENT")
    print(
        """
_GROUT_SOCK_PATH_
\tPath to the control plane API socket. If not set, defaults to
\t_/run/grout.sock_."""
    )
    print(
        """
_DPRC_
\tSet the DPRC - Datapath Resource Container: This value should match the one
\tused by DPDK during the scan of the fslmc bus. It is recommended to set
\tthis on any NXP QorIQ targets. This serves as the entry point for grcli to
\tenable autocompletion of fslmc devices manageable by grout. While grcli can
\tconfigure grout without this environment setting, autocompletion of the
\tdevargs will not be available."""
    )

    pages = []

    for ctx in tree.children[2].children:
        if ctx.type != "seq":
            continue
        pages.append(f"*grcli-{ctx.children[0].desc}*(1)")

    print_trailer(pages + ["*grout*(8)"])


def walk_arguments(cmd: Node, options: dict, arguments: list, in_option: bool):
    for c in cmd.children:
        if c.type in ("or", "seq", "cmd", "option", "subset", "many"):
            args = []
            walk_arguments(
                c, options, args, in_option or c.type in ("option", "subset")
            )
            if c.type == "or":
                arguments.append("(" + "|".join(args) + ")")
            elif c.type in ("seq", "cmd", "subset", "option"):
                arg = " ".join(args)
                if in_option:
                    arg = f"[{arg}]"
                arguments.append(arg)
            elif c.type == "many":
                arguments.append(" ".join(args) + "+")
        elif c.type == "str":
            arguments.append(f"*{c.desc}*")
        else:
            if c.help:
                options[c.id] = c.help
            arguments.append(f"_{c.id}_")


def print_command_synopsis(node: Node, options: dict, stack: list):
    arguments = [f"*{s}*" for s in stack]
    walk_arguments(node, options, arguments, False)
    print()
    print(" ".join(arguments))
    print(f"\t{node.help}")


def walk_commands(node: Node, options: dict, stack: list):
    if node.has_cb:
        print_command_synopsis(node, options, stack)
    else:
        for c in node.children:
            if c.type == "str":
                stack.append(c.desc)
            elif c.type in ("or", "seq", "cmd", "option", "subset"):
                walk_commands(c, options, stack)
        for c in node.children:
            if c.type == "str":
                stack.pop()


def print_context_page(tree: Node, context: str):
    for ctx in tree.children[2].children:
        if ctx.type != "seq":
            continue
        if ctx.children[0].desc == context:
            base = ctx
            break
    else:
        raise FileNotFoundError(context)

    print_header(f"grcli-{context}", base.children[0].help)

    options = {}
    walk_commands(ctx, options, [])

    if options:
        print()
        print("# OPTIONS")

    pages = {"*grcli*(1)"}

    for opt, desc in options.items():
        print()
        print(f"_{opt}_")
        print(f"\t{desc}")
        if opt in ("IFACE", "INTERFACE", "NAME") and context != "interface":
            pages.add("*grcli-interface*(1)")
        elif opt in ("NH", "NH_ID", "SEGLIST") and context != "nexthop":
            pages.add("*grcli-nexthop*(1)")
        elif opt == "VRF" and context != "route":
            pages.add("*grcli-route*(1)")
        elif opt in ("ADDR", "IP", "DEST") and context != "address":
            pages.add("*grcli-address*(1)")

    print_trailer(pages)


def dict_to_node(d: dict) -> Node:
    return Node(
        type=d["type"],
        desc=d["desc"],
        has_cb=d["has_cb"],
        id=d["id"],
        help=d["help"],
        children=d["children"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--file", default="-")
    parser.add_argument("context", nargs="?")
    args = parser.parse_args()

    if args.file == "-":
        tree = json.load(sys.stdin, object_hook=dict_to_node)
    else:
        with open(args.file) as file:
            tree = json.load(file, object_hook=dict_to_node)
    if args.context:
        print_context_page(tree, args.context)
    else:
        print_main_page(tree)


if __name__ == "__main__":
    main()
