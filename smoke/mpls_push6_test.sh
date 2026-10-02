#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 2001:db8:0::1/64 iface p0
grcli address add 2001:db8:1::1/64 iface p1

# MPLS nexthop: push label 100 for IPv6 traffic, forward via n1
grcli nexthop add mpls iface p1 via 2001:db8:1::2 labels 100 id 42

# IPv6 route pointing to MPLS nexthop
grcli route add fd00::/64 via id 42

# return path (plain IPv6)
grcli route add fd00:0:0:1::/64 via 2001:db8:0::2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 2001:db8:$n::2/64 dev $p
done

# n0: plain IPv6 sender
ip -n n0 addr add fd00:0:0:1::1/128 dev lo
ip -n n0 route add default via 2001:db8:0::1

# n1: MPLS receiver, pop label 100
ip netns exec n1 sysctl -wq net.mpls.platform_labels=1000
ip netns exec n1 sysctl -wq net.mpls.conf.x-p1.input=1
ip -n n1 addr add fd00::1/128 dev lo
ip -n n1 -f mpls route add 100 dev lo

# return path from n1
ip -n n1 route add default via 2001:db8:1::1

# plain IPv6 -> grout pushes MPLS label -> n1 pops label
ip netns exec n0 ping6 -i0.01 -c3 -n fd00::1
