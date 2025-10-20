#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

# setup ports and connected
port_add $p0
port_add $p1
grcli address add fd00:102::1/64 iface $p1
grcli address add 192.168.61.1/24 iface $p0

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
done
ip -n $p0 addr add 192.168.61.2/24 dev $p0
ip -n $p1 addr add fd00:102::2/64 dev $p1

sleep 3

#
# network layout:
#  (client) p0(netns) <--> p0 <grout> p1 <--->  p1(netns) (public: 192.168.60.1/24 on p0)
#       ipv4 ---------------|        srv6        |-- ipv4
#
# test case:
#   - (1) send ipv4 ping from p0
#   - (2) grout encap in srv6, send to sid fd00:202::2
#   - (3) linux p1 decap it
#   - (4) reply to ping
#   - (5) linux p1 reencap in srv6, send to grout sid fd00:202::100,
#   - (6) grout decap it, reply back in ipv4 to p0
#

# only linux's p1 will see srv6
ip netns exec $p1 sysctl -w net.ipv6.conf.$p1.seg6_enabled=1
ip netns exec $p1 sysctl -w net.ipv6.conf.$p1.forwarding=1

# (1) send ipv4 to grout
ip -n $p0 route add default via 192.168.61.1 dev $p0

# (2)
grcli nexthop add srv6 seglist fd00:202::2 id 42
grcli route add 192.168.0.0/16 via id 42
grcli route add fd00:202::/64 via fd00:102::2

# (3)
ip -n $p1 -6 route add fd00:202::2 encap seg6local action End.DX4 nh4 192.168.60.1 count dev $p1

# (4) 192.168.60.0/24 is our 'public' network
ip -n $p1 addr add 192.168.60.1/24 dev $p1

# (5)
ip -n $p1 route add 192.168.61.0/24 encap seg6 mode encap segs fd00:202::100 dev $p1
ip -n $p1 -6 route add fd00:202::/64 via fd00:102::1 dev $p1

# (6)
grcli nexthop add srv6-local behavior end.dt4 id 666
grcli route add fd00:202::100/128 via id 666

# test
ip netns exec $p0 ping -c 3 192.168.60.1
# check that sid is reachable
ip netns exec $p1 ping6 -c 3 fd00:202::100
