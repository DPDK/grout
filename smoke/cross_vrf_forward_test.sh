#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init.sh

port_add p0 vrf 1
port_add p1 vrf 2
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# from 16.0.0.1 to 16.1.0.1, only one route lookup is done
grcli nexthop add l3 iface p1 id 2 address 172.16.1.2
grcli route add 16.1.0.0/16 via id 2 vrf 1
grcli route add 16.1.0.0/16 via id 2 vrf 2 # required for ARP resolution

# from 16.1.0.1 to 16.0.0.1, two route lookup are done
grcli nexthop add l3 iface gr-loop1 id 1
grcli route add 16.0.0.0/16 via id 1 vrf 2
grcli route add 16.0.0.0/16 via 172.16.0.2 vrf 1

for n in 0 1; do
	p=p$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p addr add 16.$n.0.1/16 dev lo
	ip -n $p route add default via 172.16.$n.1
done

ip netns exec p0 ping -i0.01 -c3 -I 16.0.0.1 -n 16.1.0.1
ip netns exec p1 ping -i0.01 -c3 -I 16.1.0.1 -n 16.0.0.1
