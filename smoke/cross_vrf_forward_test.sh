#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

for n in 0 1; do
	p=$run_id$n
	port_add $p 40$n vrf $((n + 1))
	grcli address add 172.16.$n.1/24 iface $p
	netns_add $p 40$n
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p addr add 16.$n.0.1/16 dev lo
	ip -n $p link set lo up
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

# from 16.0.0.1 to 16.1.0.1, only one route lookup is done
grcli nexthop add l3 iface $p1 id 2 address 172.16.1.2
grcli route add 16.1.0.0/16 via id 2 vrf 1
grcli route add 16.1.0.0/16 via id 2 vrf 2 # required for ARP resolution

# from 16.1.0.1 to 16.0.0.1, two route lookup are done
grcli nexthop add l3 iface gr-loop1 id 1
grcli route add 16.0.0.0/16 via id 1 vrf 2
grcli route add 16.0.0.0/16 via 172.16.0.2 vrf 1

ip netns exec $p0 ping -i0.01 -c3 -I 16.0.0.1 -n 16.1.0.1
ip netns exec $p1 ping -i0.01 -c3 -I 16.1.0.1 -n 16.0.0.1
