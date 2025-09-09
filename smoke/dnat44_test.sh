#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli add interface port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00
grcli add interface port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:01
grcli add ip address 172.16.0.1/24 iface $p0
grcli add ip address 10.99.0.1/24 iface $p1
grcli add policy dnat44 interface $p0 destination 172.16.0.99 replace 10.99.0.99
grcli show policy dnat44
grcli show nexthop

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:ca:00:0$n
	ip -n $p link set $p up
	ip -n $p link set lo up
done

ip -n $p0 addr add 172.16.0.2/24 dev $p0
ip -n $p1 addr add 10.99.0.99/24 dev $p1
ip -n $p1 route add default via 10.99.0.1

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.0.99

grcli show policy dnat44
grcli show nexthop
