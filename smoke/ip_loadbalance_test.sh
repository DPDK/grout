#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#
#                  p0 (.0.2)     |               |
# 192.200.0.2  lo             n0 | --- grout --- | n1  p2  172.16.2.2
#                  p1 (.1.2)     |               |
#
. $(dirname $0)/_init.sh

port_add p0
port_add p1
port_add p2

netns_add n0
ip link set x-p0 netns n0
ip link set x-p1 netns n0
ip -n n0 addr add 192.200.0.2/24 dev lo
ip -n n0 link set x-p0 up
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 link set x-p1 up
ip -n n0 addr add 172.16.1.2/24 dev x-p1
ip -n n0 nexthop add id 1601 via 172.16.0.1 dev x-p0
ip -n n0 nexthop add id 1611 via 172.16.1.1 dev x-p1
ip -n n0 nexthop add id 1620 group 1601/1611
ip -n n0 route add 172.16.2.0/24 nhid 1620

netns_add n1
ip link set x-p2 netns n1
ip -n n1 link set x-p2 up
ip -n n1 addr add 172.16.2.2/24 dev x-p2
ip -n n1 route add default via 172.16.2.1

grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli address add 172.16.2.1/24 iface p2

# Add ECMP route
grcli nexthop add l3 iface p0 address 172.16.0.2 id 100
grcli nexthop add l3 iface p1 address 172.16.1.2 id 101
grcli nexthop add group id 10 member 100 member 101
grcli route add 192.200.0.0/24 via id 10

# Locally generated ICMP requests
grcli ping 192.200.0.2 count 1 ident 1 delay 10
grcli ping 192.200.0.2 count 1 ident 2 delay 10

# Externally generated ICMP requests
ip netns exec n0 ping -i0.01 -c3 -n 192.200.0.2
