#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

wait_member_sync() {
	local iface=$1
	local attempts=0

	while [ "$attempts" -lt 20 ]; do
		if ip -n n0 -d link show $iface | \
			grep -q '<.*\<in_sync\>.*> .* <.*\<in_sync\>.*>'
		then
			return 0
		fi
		sleep 0.2
		attempts=$((attempts + 1))
	done

	ip -n n0 -d link show $iface
	fail "$iface member not synced"
}

. $(dirname $0)/_init.sh

grcli interface add bond bond0 mode lacp
port_add p0 domain bond0
port_add p1 domain bond0
port_add p2 domain bond0
grcli address add 172.16.0.1/24 iface bond0

netns_add n0
ip -n n0 link add bond0 type bond mode 802.3ad \
	lacp_active on lacp_rate fast xmit_hash_policy layer3+4
for p in x-p0 x-p1 x-p2; do
	ip link set $p netns n0
	ip -n n0 link set $p master bond0
	ip -n n0 link set $p up
done
ip -n n0 link set bond0 up
ip -n n0 addr add 172.16.0.2/24 dev bond0
for p in x-p0 x-p1 x-p2; do
	wait_member_sync $p
done

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1
grcli ping 172.16.0.2 delay 10 count 3
