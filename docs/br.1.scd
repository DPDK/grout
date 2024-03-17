BR(1)
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2024 Robin Jarry

# NAME

*br* -- boring router

# DESCRIPTION

*br* is a software router.

# SYNOPSIS

*br* [*-h*] [*-t*] [*-c* _FILE_] [*-s* _PATH_]

# OPTIONS

*-v*, *--verbose*
	Increase verbosity.
*-t*, *--test-mode*
	Run in test mode (no hugepages).
*-s* _PATH_, *--socket* _PATH_
	Path the control plane API socket.

	Default: *BR_SOCK_PATH* from env or _/run/br.sock_).

# AUTHORS

Created and maintained by Robin Jarry.
