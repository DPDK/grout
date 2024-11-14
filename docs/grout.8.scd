GROUT(8)
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2024 Robin Jarry

# NAME

*grout* -- graph router daemon

# DESCRIPTION

Grout is a software router based on DPDK rte_graph.

# SYNOPSIS

; Please keep flags/options in alphabetical order.

*grout* [*-h*] [*-L* _<type>:<level>_] [*-p*] [*-s* _<path>_] [*-t*] [*-T*
_<regexp>_] [*-B* _<size>_] [*-D* _<path>_] [*-M* _<mode>_] [*-x*] [*-v*] [*-V*]


# OPTIONS

*-h*, *--help*
	Display usage help.

*-p*, *--poll-mode*
	Disable automatic micro-sleep.

*-s*, *--socket* _<path>_
	Path the control plane API socket.

	Default: *GROUT_SOCK_PATH* from environment or _/run/grout.sock_).

*-t*, *--test-mode*
	Run in test mode (no huge pages).

*-V*, *--version*
	Print version and exit.

*-v*, *--verbose*
	Increase verbosity. Can be specified multiple times.

*-x*, *--trace-packets*
	Print all ingress/egress packets (for debugging purposes).

*-L*, *--log-level* _<type>:<level>_
	Specify log level for a specific component. For example:

		*--log-level* _lib.eal:debug_

	Can be specified multiple times.

*-T*, *--trace* _<regexp>_
	Enable trace based on regular expression trace name. By default, the
	trace is disabled. User must specify this option to enable trace. For
	example:

	Global trace configuration for EAL only:
		*--trace* _eal_
	Global trace configuration for ALL the components:
		*--trace* _.\*_

	Can be specified multiple times up to 32 times.

*-D*, *--trace-dir* _<path>_
	Specify trace directory for trace output. For example:

		*--trace-dir* _/tmp_

	By default, trace output will created at home directory and parameter
	must be specified once only.

*-B*, *--trace-bufsz* _<size>_
	Specify maximum size of allocated memory for trace output for each
	thread. Valid unit can be either B or K or M for Bytes, KBytes and
	MBytes respectively. For example:

		*--trace-bufsz* _2M_

	By default, size of trace output file is 1MB and parameter must be
	specified once only.

*-M*, *--trace-mode* _o|overwrite|d|discard_
	Specify the mode of update of trace output file. Either update on a file
	can be wrapped or discarded when file size reaches its maximum limit.
	For example:

		*--trace-mode* _discard_

	Default mode is _overwrite_ and parameter must be specified once only.

# AUTHORS

Created and maintained by Robin Jarry.
