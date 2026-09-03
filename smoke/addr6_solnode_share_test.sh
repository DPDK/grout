#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy

# Verify that addresses sharing a solicited-node multicast group are
# independent.
#
# fd00:1::9 and fd00:2::9 both map to ff02::1:ff00:9, so p0 joins that group
# once for the two of them. Removing one address must not unsubscribe the
# group, otherwise the remaining address stops receiving neighbor
# solicitations and becomes unreachable.

. $(dirname $0)/_init.sh

port_add p0
grcli address add fd00:1::1/64 iface p0
grcli address add fd00:1::9/128 iface p0
grcli address add fd00:2::9/128 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add fd00:1::2/64 dev x-p0

ip netns exec n0 ping -6 -i0.01 -c3 -W1 -n fd00:1::9 || fail "ping to fd00:1::9 failed"

grcli address del fd00:2::9/128 iface p0

ip -n n0 -6 neigh flush all
ip netns exec n0 ping -6 -i0.01 -c3 -W1 -n fd00:1::9 ||
	fail "fd00:1::9 unreachable after deleting fd00:2::9"
