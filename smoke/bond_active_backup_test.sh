#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

wait_member_active() {
	local iface=$1
	local attempts=0
	while [ "$attempts" -lt 20 ]; do
		if bridge -n n0 fdb show br br0 brport "$iface" state reachable | grep -F "$mac"; then
			return 0
		fi
		sleep 0.2
		attempts=$((attempts + 1))
	done
	fail "bond member $iface not active"
}

. $(dirname $0)/_init.sh

port_add p0
port_add p1
port_add p2

mac=02:f0:00:b4:44:44

netns_add n0
ip -n n0 link add br0 type bridge vlan_filtering 1
for p in p0 p1 p2; do
	ip link set $p netns n0
	ip -n n0 link set $p master br0
	ip -n n0 link set $p up
done
ip -n n0 link set br0 up
ip -n n0 addr add 172.16.0.2/24 dev br0

grcli interface add bond bond0 mode active-backup member p0
grcli interface set bond bond0 mode active-backup member p0 member p1 member p2 mac $mac primary p1
grcli address add 172.16.0.1/24 iface bond0

wait_member_active p1

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1

ip -n n0 link set p1 down
wait_member_active p0

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1

ip -n n0 link set p1 up
wait_member_active p1

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1
