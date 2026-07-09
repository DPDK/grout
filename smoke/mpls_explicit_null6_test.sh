#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 2001:db8:0::1/64 iface p0
grcli address add 2001:db8:1::1/64 iface p1

# IPv6 route for the decapsulated packet (no MPLS nexthop needed)
grcli route add fd00::/64 via 2001:db8:1::2

# return path
grcli route add fd00:0:0:1::/64 via 2001:db8:0::2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 2001:db8:$n::2/64 dev $p
done

# n0: push IPv6 Explicit NULL (label 2)
ip -n n0 addr add fd00:0:0:1::1/128 dev lo
ip -n n0 route add fd00::/64 encap mpls 2 via 2001:db8:0::1 dev x-p0

# n1: plain IPv6 receiver
ip -n n1 addr add fd00::1/128 dev lo
ip -n n1 route add default via 2001:db8:1::1

# resolve NDP before MPLS test
ip netns exec n0 ping6 -c1 -n 2001:db8:0::1

# n0 pushes MPLS(label=2) -> grout strips and routes via ip6_input -> n1 receives plain IPv6
ip netns exec n0 ping6 -i0.01 -c3 -n fd00::1
