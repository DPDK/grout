#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#
#                                   |     x-p1 (.1.2)
#  [x-p0 n0] --- p0 grout p1,p2 --- | n1             lo
#                                   |     x-p2 (.2.2)
#
. $(dirname $0)/_init_frr.sh

create_interface p0
create_interface p1
create_interface p2

netns_add n0
ip link set x-p0 netns n0
ip -n n0 link set x-p0 up
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 route add default via 172.16.0.1

netns_add n1
ip link set x-p1 netns n1
ip link set x-p2 netns n1
ip -n n1 addr add 192.0.0.2/32 dev lo
ip -n n1 link set x-p1 up
ip -n n1 addr add 172.16.1.2/24 dev x-p1
ip -n n1 link set x-p2 up
ip -n n1 addr add 172.16.2.2/24 dev x-p2

set_ip_address p0 172.16.0.1/24
set_ip_address p1 172.16.1.1/24
set_ip_address p2 172.16.2.1/24

set_ip_route 192.0.0.0/24 172.16.1.2
# Can't use set_ip_route a second time
# as the helper will look for the route
# --> Configure it manually
vtysh <<-EOF
	configure terminal
	ip route 192.0.0.0/24 172.16.2.2
EOF

ip -n n1 route add default via 172.16.1.1
ip netns exec n0 ping -i0.01 -c3 -n 192.0.0.2

ip -n n1 route del default
ip -n n1 route add default via 172.16.2.1
ip netns exec n0 ping -i0.01 -c3 -n 192.0.0.2
