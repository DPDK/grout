#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

port_add p1
port_add p2

grcli address add fd00:ba4:1::1/64 iface p1
grcli address add fd00:ba4:2::1/64 iface p2

for n in 1 2; do
	p=p$n
	ns=n$n
	netns_add $ns
	ip link set $p netns $ns
	ip -n $ns link set $p up
	ip -n $ns addr add fd00:ba4:$n::2/64 dev $p
	ip -n $ns route add default via fd00:ba4:$n::1
done

sleep 3  # wait for DAD

ip netns exec n1 ping6 -i0.01 -c3 -n $(llocal_addr p1)
ip netns exec n2 ping6 -i0.01 -c3 -n $(llocal_addr p2)
ip netns exec n1 ping6 -i0.01 -c3 -n $(llocal_addr p2) && fail "Unexpected answer from foreign link local address"
ip netns exec n1 ping6 -i0.01 -c3 -n fd00:ba4:2::2
ip netns exec n2 ping6 -i0.01 -c3 -n fd00:ba4:1::2
ip netns exec n1 ping6 -i0.01 -c3 -n fd00:ba4:1::1
ip netns exec n2 ping6 -i0.01 -c3 -n fd00:ba4:2::1
ip netns exec n1 traceroute -N1 -n fd00:ba4:2::2
ip netns exec n2 traceroute -N1 -n fd00:ba4:1::2
