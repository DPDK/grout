#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1
p2=${run_id}2

grcli interface add port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00
grcli interface add port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:01
grcli interface add port $p2 devargs net_tap2,iface=$p2 mac f0:0d:ac:dc:00:02

grcli address add 172.16.0.1/24 iface $p0
grcli address add 172.16.1.1/24 iface $p1
grcli address add 172.16.2.1/24 iface $p2

netns_add ${run_id}
ip -n ${run_id} link set lo up
ip -n ${run_id} addr add 192.200.0.2/24 dev lo

for n in 0 1; do
	p=$run_id$n
	ip link set $p netns ${run_id}
	ip -n ${run_id} link set $p address ba:d0:ca:ca:00:0$n
	ip -n ${run_id} link set $p up
	ip -n ${run_id} addr add 172.16.$n.2/24 dev $p
done

# Add ECMP route
grcli nexthop add l3 iface $p0 address 172.16.0.2 id 100
grcli nexthop add l3 iface $p1 address 172.16.1.2 id 101
grcli nexthop add group id 10 member 100 member 101
grcli route add 192.200.0.0/24 via id 10

# Locally generated ICMP requests
grcli ping 192.200.0.2 count 1 ident 1
grcli ping 192.200.0.2 count 1 ident 2

# Externally generated ICMP requests
ip -n ${run_id} nexthop add id 1601 via 172.16.0.1 dev $p0
ip -n ${run_id} nexthop add id 1611 via 172.16.1.1 dev $p1
ip -n ${run_id} nexthop add id 1620 group 1601/1611

ip -n ${run_id} route add 172.16.2.0/24 nhid 1620

netns_add $p2
ip link set $p2 netns $p2
ip -n $p2 link set $p2 address ba:d0:ca:ca:00:02
ip -n $p2 link set $p2 up
ip -n $p2 addr add 172.16.2.2/24 dev $p2
ip -n $p2 route add default via 172.16.2.1
ip netns exec $p2 ping 192.200.0.2 -c 3

grcli nexthop del 10
