#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

p1=${run_id}1
p2=${run_id}2

for n in 1 2; do
	p=$run_id$n
	create_interface $p 40$n
	netns_add $p 40$n
	ip -n $p addr add fd00:ba4:$n::2/64 dev $p
	if [[ $n -eq 1 ]]; then
		ip -n $p addr add fd00:f00:$n::2/64 dev lo
	else
		ip -n $p addr add fd00:f00:$n::2/64 dev $p
	fi
	ip -n $p route add default via fd00:ba4:$n::1
	set_ip_address $p fd00:ba4:$n::1/64
done

set_ip_route fd00:f00:1::/64 fd00:ba4:1::2
set_ip_route fd00:f00:2::/64 $p2

sleep 3  # wait for DAD

ip netns exec $p1 ping6 -i0.01 -c3 -n $(llocal_addr $p1)
ip netns exec $p2 ping6 -i0.01 -c3 -n $(llocal_addr $p2)
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
