#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 10.99.0.1/24 iface p1
grcli dnat44 add interface p0 destination 172.16.0.99 replace 10.99.0.99
grcli dnat44 show
grcli nexthop show

for n in 0 1; do
	p=p$n
	ns=n$n
	netns_add $ns
	ip link set $p netns $ns
	ip -n $ns link set $p up
done

ip -n n0 addr add 172.16.0.2/24 dev p0
ip -n n1 addr add 10.99.0.99/24 dev p1
ip -n n1 route add default via 10.99.0.1

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.99

grcli dnat44 show
grcli nexthop show type dnat
