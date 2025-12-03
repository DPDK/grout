#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

create_interface p0 vrf 1
create_interface p1 vrf 1
create_interface p2 vrf 2
create_interface p3 vrf 2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $ns addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $ns route add default via 172.16.$((n % 2)).1
done
set_ip_address p0 172.16.0.1/24
set_ip_address p1 172.16.1.1/24
set_ip_route 16.0.0.0/16 172.16.0.2 1
set_ip_route 16.1.0.0/16 172.16.1.2 1

for n in 2 3; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$((n % 2)).2/24 dev $p
	ip -n $ns addr add 16.$((n % 2)).0.1/16 dev lo
	ip -n $ns route add default via 172.16.$((n % 2)).1
done
set_ip_address p2 172.16.0.1/24
set_ip_address p3 172.16.1.1/24
set_ip_route 16.0.0.0/16 172.16.0.2 2
set_ip_route 16.1.0.0/16 172.16.1.2 2

ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec n2 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n2 ping -i0.01 -c3 -n 16.1.0.1
