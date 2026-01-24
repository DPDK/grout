#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

grcli interface add bridge br0

port_add p0 domain br0
port_add p1 domain br0
port_add p2 domain br0

grcli interface show name br0

grcli address add 172.16.0.1/24 iface br0

for n in 0 1 2; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.0.1$n/24 dev $p
	ip -n $ns route add default via 172.16.0.1
done

ip netns exec n0 ping -i0.01 -c3 -W1 -n 172.16.0.11 || fail "L2 ping n0->n1 failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 172.16.0.12 || fail "L2 ping n1->n2 failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 172.16.0.10 || fail "L2 ping n2->n0 failed"

for n in 0 1 2; do
	mac=$(ip netns exec n$n cat /sys/class/net/x-p$n/address)
	grcli fdb show iface p$n learn | grep -F "$mac"
done

# overwrite dynamic learned fdb entry with static one
mac=$(ip netns exec n0 cat /sys/class/net/x-p0/address)
grcli fdb add "$mac" iface p0
grcli fdb show iface p0 static | grep -F "$mac"

grcli ping 172.16.0.10 count 3 delay 10

ip netns exec n0 ping -i0.01 -c3 -W1 -n 172.16.0.1 || fail "L3 ping n0->bridge failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 172.16.0.1 || fail "L3 ping n1->bridge failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 172.16.0.1 || fail "L3 ping n2->bridge failed"

grcli interface set port p1 vrf main
if grcli fdb show iface p1 | grep .; then
	fail "fdb still contains entries for removed interface"
fi

grcli interface del br0
if grcli fdb show | grep .; then
	fail "fdb still contains entries"
fi
