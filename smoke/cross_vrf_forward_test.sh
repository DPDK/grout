#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli add interface port $p0 devargs net_tap0,iface=$p0 vrf 1 mac f0:0d:ac:dc:01:00
grcli add interface port $p1 devargs net_tap1,iface=$p1 vrf 2 mac f0:0d:ac:dc:01:01
grcli add ip address 172.16.0.1/24 iface $p0
grcli add ip address 172.16.1.1/24 iface $p1

# from 16.0.0.1 to 16.1.0.1, only one route lookup is done
grcli add nexthop id 2 address 172.16.1.2 iface $p1
grcli add ip route 16.1.0.0/16 via id 2 vrf 1

# from 16.1.0.1 to 16.0.0.1, two route lookup are done
grcli add nexthop id 1 iface gr-loop1
grcli add ip route 16.0.0.0/16 via id 1 vrf 2
grcli add ip route 16.0.0.0/16 via 172.16.0.2 vrf 1

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:ca:01:0$n
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p addr add 16.$n.0.1/16 dev lo
	ip -n $p link set lo up
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec $p0 ping -i0.01 -c3 -I 16.0.0.1 -n 16.1.0.1
ip netns exec $p1 ping -i0.01 -c3 -I 16.1.0.1 -n 16.0.0.1
