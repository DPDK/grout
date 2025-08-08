#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

p1=${run_id}1
p2=${run_id}2

create_interface $p1 d2:f0:0c:ba:a4:11
create_interface $p2 d2:f0:0c:ba:a4:12

for n in 1 2; do
	p=$run_id$n
	netns_add n-$p
	ip link set $p netns n-$p
	ip -n n-$p link set $p address d2:ad:ca:ca:a4:1$n
	ip -n n-$p link set $p up
	ip -n n-$p link set lo up
	ip -n n-$p addr add fd00:ba4:$n::2/64 dev $p
	if [[ $n -eq 1 ]]; then
		ip -n n-$p addr add fd00:f00:$n::2/64 dev lo
	else
		ip -n n-$p addr add fd00:f00:$n::2/64 dev $p
	fi
	ip -n n-$p route add default via fd00:ba4:$n::1
	ip -n n-$p addr show
done

set_ip_address $p1 fd00:ba4:1::1/64
set_ip_address $p2 fd00:ba4:2::1/64
set_ip_route fd00:f00:1::/64 fd00:ba4:1::2
set_ip_route fd00:f00:2::/64 $p2

sleep 3  # wait for DAD

ip netns exec n-$p1 ping6 -i0.01 -c3 -n fe80::d2f0:cff:feba:a411
ip netns exec n-$p2 ping6 -i0.01 -c3 -n fe80::d2f0:cff:feba:a412
ip netns exec n-$p1 ping6 -i0.01 -c3 -n fd00:f00:2::2
ip netns exec n-$p2 ping6 -i0.01 -c3 -n fd00:f00:1::2
ip netns exec n-$p1 ping6 -i0.01 -c3 -n fd00:ba4:2::2
ip netns exec n-$p2 ping6 -i0.01 -c3 -n fd00:ba4:1::2
ip netns exec n-$p1 ping6 -i0.01 -c3 -n fd00:ba4:1::1
ip netns exec n-$p2 ping6 -i0.01 -c3 -n fd00:ba4:2::1
ip netns exec n-$p1 traceroute -N1 -n fd00:ba4:2::2
ip netns exec n-$p2 traceroute -N1 -n fd00:ba4:1::2
ip netns exec n-$p1 traceroute -N1 -n fd00:f00:2::2
ip netns exec n-$p2 traceroute -N1 -n fd00:f00:1::2
