#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli interface add vlan p0.42 parent p0 vlan_id 42
grcli interface add vlan p1.43 parent p1 vlan_id 43
grcli address add 172.16.0.1/24 iface p0.42
grcli address add 172.16.1.1/24 iface p1.43

for n in 0 1; do
	p=p$n
	v=$p.$((n+42))
	netns_add $p
	ip link set $p netns $p
	ip -n $p link add $v link $p type vlan id $((n+42))
	ip -n $p link set $p up
	ip -n $p link set $v up
	ip -n $p addr add 172.16.$n.2/24 dev $v
	ip -n $p route add default via 172.16.$n.1
done

ip netns exec p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec p1 ping -i0.01 -c3 -n 172.16.0.2
