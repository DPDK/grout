#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli interface add vrf gr-vrf1
grcli interface add vrf gr-vrf2
port_add p0 vrf gr-vrf1
port_add p1 vrf gr-vrf1
port_add p2 vrf gr-vrf2
port_add p3 vrf gr-vrf2
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli route add 16.0.0.0/16 via 172.16.0.2 vrf gr-vrf1
grcli route add 16.1.0.0/16 via 172.16.1.2 vrf gr-vrf1
grcli address add 172.16.0.1/24 iface p2
grcli address add 172.16.1.1/24 iface p3
grcli route add 16.0.0.0/16 via 172.16.0.2 vrf gr-vrf2
grcli route add 16.1.0.0/16 via 172.16.1.2 vrf gr-vrf2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $ns addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $ns route add default via 172.16.$((n % 2)).1
done
ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n0 ping -i0.01 -c3 -n 16.1.0.1

for n in 2 3; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $ns addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $ns route add default via 172.16.$((n % 2)).1
done
ip netns exec n2 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n2 ping -i0.01 -c3 -n 16.1.0.1
