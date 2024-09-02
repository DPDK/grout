GROUT(8)
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2024 Robin Jarry

# NAME

*grout* -- graph router daemon

# DESCRIPTION

Grout is a software router based on DPDK rte_graph.

# SYNOPSIS

; Please keep flags/options in alphabetical order.

*grout* [*-h*] [*-p*] [*-s* _PATH_] [*-t*] [*-v*] [*-x*]

# OPTIONS

*-h*, *--help*
	Display usage help.
*-p*, *--poll-mode*
	Disable automatic micro-sleep.
*-s* _PATH_, *--socket* _PATH_
	Path the control plane API socket.

	Default: *GROUT_SOCK_PATH* from environment or _/run/grout.sock_).
*-t*, *--test-mode*
	Run in test mode (no huge pages).
*-v*, *--verbose*
	Increase verbosity. Can be specified multiple times.
*-x*, *--trace-packets*
	Print all ingress/egress packets (for debugging purposes).

# AUTHORS

Created and maintained by Robin Jarry.
