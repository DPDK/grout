#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p1=${run_id}1
p2=${run_id}2

grcli add interface port $p1 devargs net_tap0,iface=$p1 mac d2:f0:0c:ba:a4:11
grcli add interface port $p2 devargs net_tap1,iface=$p2 mac d2:f0:0c:ba:a4:12
grcli add ip6 address fd00:ba4:1::1/64 iface $p1
grcli add ip6 address fd00:ba4:2::1/64 iface $p2
grcli add ip6 route fd00:f00:1::/64 via fd00:ba4:1::2
grcli add ip6 route fd00:f00:2::/64 via fd00:ba4:2::2

for n in 1 2; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address d2:ad:ca:ca:a4:1$n
	ip -n $p link set $p up
	ip -n $p link set lo up
	ip -n $p addr add fd00:ba4:$n::2/64 dev $p
	ip -n $p addr add fd00:f00:$n::2/64 dev lo
	ip -n $p route add default via fd00:ba4:$n::1
	ip -n $p addr show
done

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
