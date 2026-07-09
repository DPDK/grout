# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

# Grout handles MPLS in its own datapath, but these tests also need the peer
# network namespaces to push/pop labels, which requires kernel MPLS. These
# modules are not loaded by default on all systems, and without them the
# net.mpls.* sysctls and "encap mpls" routes used by the tests fail outright.
modprobe mpls_router 2>/dev/null || true
modprobe mpls_iptunnel 2>/dev/null || true
if [ ! -d /proc/sys/net/mpls ]; then
	echo "$0: kernel MPLS support (mpls_router) is not available"
	exit 125
fi
