#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1
v0=$p0.42
v1=$p1.43

for n in 0 1; do
	p=$run_id$n
	vlan=$((n + 42))
	v=$p.$vlan
	port_add $p $vlan
	bridge vlan del dev $p vid $vlan
	bridge vlan add dev $p vid $vlan
	grcli interface add vlan $v parent $p vlan_id $vlan
	grcli address add 172.16.$((n % 2)).1/24 iface $v
	netns_add $p $vlan
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2
