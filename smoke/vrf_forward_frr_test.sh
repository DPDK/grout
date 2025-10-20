#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

p0=${run_id}0
p1=${run_id}1
p2=${run_id}2
p3=${run_id}3

for n in 0 1; do
	p=$run_id$n
	x=$((n % 2))
	create_interface $p vrf 1
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$x.2/24 dev $p
	ip -n $p addr add 16.$x.0.1/16 dev lo
	ip -n $p route add default via 172.16.$x.1
	set_ip_address $p 172.16.$x.1/24
	set_ip_route 16.$x.0.0/16 172.16.$x.2 1
done

for n in 2 3; do
	p=$run_id$n
	x=$((n % 2))
	create_interface $p vrf 2
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$x.2/24 dev $p
	ip -n $p addr add 16.$x.0.1/16 dev lo
	ip -n $p route add default via 172.16.$x.1
	set_ip_address $p 172.16.$x.1/24
	set_ip_route 16.$x.0.0/16 172.16.$x.2 2
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec $p2 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p2 ping -i0.01 -c3 -n 16.1.0.1
