GROUT(1)
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2024 Robin Jarry

# NAME

*grout* -- graph router daemon

# DESCRIPTION

Grout is a software router based on DPDK rte_graph.

# SYNOPSIS

*grout* [*-h*] [*-t*] [*-c* _FILE_] [*-s* _PATH_]

# OPTIONS

*-v*, *--verbose*
	Increase verbosity.
*-t*, *--test-mode*
	Run in test mode (no huge pages).
*-s* _PATH_, *--socket* _PATH_
	Path the control plane API socket.

	Default: *GROUT_SOCK_PATH* from environment or _/run/grout.sock_).

# AUTHORS

Created and maintained by Robin Jarry.
