#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#
#                         |   p1 (.1.2)
#  [p0 ns0] --- grout --- | ns1          lo
#                         |   p2 (.2.2)
#
#
#
. $(dirname $0)/_init_frr.sh

p0=${run_id}0
p1=${run_id}1
p2=${run_id}2

create_interface $p0 f0:0d:ac:dc:00:00
create_interface $p1 f0:0d:ac:dc:00:01
create_interface $p2 f0:0d:ac:dc:00:02

netns_add n-$p0
	ip l set $p0 netns n-$p0
	ip -n n-$p0 link set $p0 address ba:d0:ca:ca:00:00
	ip -n n-$p0 link set $p0 up
	ip -n n-$p0 link set lo up
	ip -n n-$p0 addr add 172.16.0.2/24 dev $p0
	ip -n n-$p0 route add default via 172.16.0.1

netns_add n-$p1
	ip l set $p1 netns n-$p1
	ip l set $p2 netns n-$p1
	ip -n n-$p1 link set lo up
	ip -n n-$p1 addr add 192.0.0.2/32 dev lo
	ip -n n-$p1 link set $p1 address ba:d0:ca:ca:00:01
	ip -n n-$p1 link set $p1 up
	ip -n n-$p1 addr add 172.16.1.2/24 dev $p1
	ip -n n-$p1 link set $p2 address ba:d0:ca:ca:00:02
	ip -n n-$p1 link set $p2 up
	ip -n n-$p1 addr add 172.16.2.2/24 dev $p2

set_ip_address $p0 172.16.0.1/24
set_ip_address $p1 172.16.1.1/24
set_ip_address $p2 172.16.2.1/24

set_ip_route 192.0.0.0/24 172.16.1.2
# Can't use set_ip_route a second time
# as the helper will look for the route
# --> Configure it manually
vtysh <<-EOF
	configure terminal
	ip route 192.0.0.0/24 172.16.2.2
EOF

ip -n n-$p1 route add default via 172.16.1.1
ip netns exec n-$p0  ping 192.0.0.2 -i0.01 -c 3

ip -n n-$p1 route del default
ip -n n-$p1 route add default via 172.16.2.1
ip netns exec n-$p0  ping 192.0.0.2 -i0.01 -c 3
