#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p1=${run_id}1
p2=${run_id}2

port_add $p1
port_add $p2
grcli address add fd00:ba4:1::1/64 iface $p1
grcli address add fd00:ba4:2::1/64 iface $p2
grcli route add fd00:f00:1::/64 via fd00:ba4:1::2
grcli nexthop add l3 iface $p2 id 45
grcli route add fd00:f00:2::/64 via id 45

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
