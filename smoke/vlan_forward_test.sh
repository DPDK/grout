#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1
v0=$p0.42
v1=$p1.43

port_add $p0 mac f0:0d:ac:dc:00:00
port_add $p1 mac f0:0d:ac:dc:00:01
grcli interface add vlan $v0 parent $p0 vlan_id 42
grcli interface add vlan $v1 parent $p1 vlan_id 43
grcli address add 172.16.0.1/24 iface $v0
grcli address add 172.16.1.1/24 iface $v1

for n in 0 1; do
	p=$run_id$n
	v=$p.$((n+42))
	netns_add $p
	ip link set $p netns $p
	ip -n $p link add $v link $p type vlan id $((n+42))
	ip -n $p link set $p up
	ip -n $p link set $v up
	ip -n $p addr add 172.16.$n.2/24 dev $v
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2
