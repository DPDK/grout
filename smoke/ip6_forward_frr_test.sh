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
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add fd00:ba4:$n::2/64 dev $p
	if [[ $n -eq 1 ]]; then
		ip -n $p addr add fd00:f00:$n::2/64 dev lo
	else
		ip -n $p addr add fd00:f00:$n::2/64 dev $p
	fi
	ip -n $p route add default via fd00:ba4:$n::1
done

set_ip_address $p1 fd00:ba4:1::1/64
set_ip_address $p2 fd00:ba4:2::1/64
set_ip_route fd00:f00:1::/64 fd00:ba4:1::2
set_ip_route fd00:f00:2::/64 $p2

sleep 3  # wait for DAD

ip netns exec $p1 ping6 -i0.01 -c3 -n fe80::d2f0:cff:feba:a411
ip netns exec $p2 ping6 -i0.01 -c3 -n fe80::d2f0:cff:feba:a412
ip netns exec $p1 ping6 -i0.01 -c3 -n fd00:f00:2::2
ip netns exec $p2 ping6 -i0.01 -c3 -n fd00:f00:1::2
ip netns exec $p1 ping6 -i0.01 -c3 -n fd00:ba4:2::2
ip netns exec $p2 ping6 -i0.01 -c3 -n fd00:ba4:1::2
ip netns exec $p1 ping6 -i0.01 -c3 -n fd00:ba4:1::1
ip netns exec $p2 ping6 -i0.01 -c3 -n fd00:ba4:2::1
ip netns exec $p1 traceroute -N1 -n fd00:ba4:2::2
ip netns exec $p2 traceroute -N1 -n fd00:ba4:1::2
ip netns exec $p1 traceroute -N1 -n fd00:f00:2::2
ip netns exec $p2 traceroute -N1 -n fd00:f00:1::2
