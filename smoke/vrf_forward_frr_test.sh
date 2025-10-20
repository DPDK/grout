#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

p0=${run_id}0
p1=${run_id}1
p2=${run_id}2
p3=${run_id}3

create_interface $p0 f0:0d:ac:dc:00:00 1
create_interface $p1 f0:0d:ac:dc:00:01 1
create_interface $p2 f0:0d:ac:dc:02:00 2
create_interface $p3 f0:0d:ac:dc:02:01 2

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $p addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $p route add default via 172.16.$((n % 2)).1
done
set_ip_address $p0 172.16.0.1/24
set_ip_address $p1 172.16.1.1/24
set_ip_route 16.0.0.0/16 172.16.0.2 1
set_ip_route 16.1.0.0/16 172.16.1.2 1

for n in 2 3; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $p addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $p route add default via 172.16.$((n % 2)).1
done
set_ip_address $p2 172.16.0.1/24
set_ip_address $p3 172.16.1.1/24
set_ip_route 16.0.0.0/16 172.16.0.2 2
set_ip_route 16.1.0.0/16 172.16.1.2 2

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec $p2 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p2 ping -i0.01 -c3 -n 16.1.0.1
