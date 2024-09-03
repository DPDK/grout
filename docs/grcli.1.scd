GRCLI(1)
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2024 Robin Jarry

# NAME

*grcli* -- grout command line interface

# DESCRIPTION

Grout is a software router based on DPDK rte_graph.

# SYNOPSIS

; Please keep flags/options in alphabetical order.

*grcli* [*-e*] [*-h*] [*-s* PATH] [*-x*] ...

# OPTIONS

*-e*, *--err-exit*
	Abort on first error.
*-h*, *--help*
	Show this help message and exit.
*-s* _PATH_, *--socket* _PATH_
	Path to the control plane API socket.

	Default: _GROUT_SOCK_PATH_ from env or _/run/grout.sock_).
*-x*, *--trace-commands*
	Print executed commands.

# SEE ALSO

*grout*(8) *bash-builtins*(1)

# AUTHORS

Created and maintained by Robin Jarry.
