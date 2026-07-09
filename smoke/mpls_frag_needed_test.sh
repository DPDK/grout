#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_mpls_kernel.sh
. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# MPLS nexthop: push label 100 (4 bytes overhead), forward via n1
# Effective MTU = iface_mtu(1500) - 1*4 = 1496
grcli nexthop add mpls iface p1 via 172.16.1.2 labels 100 id 42
grcli route add 10.0.1.0/24 via id 42
grcli route add 10.0.0.0/24 via 172.16.0.2 # return path

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
done

# n0: plain IP sender
ip -n n0 addr add 10.0.0.1/32 dev lo
ip -n n0 route add default via 172.16.0.1

# n1: MPLS receiver, pop label 100
ip netns exec n1 sysctl -wq net.mpls.platform_labels=1000
ip netns exec n1 sysctl -wq net.mpls.conf.x-p1.input=1
ip -n n1 addr add 10.0.1.1/32 dev lo
ip -n n1 -f mpls route add 100 dev lo
ip -n n1 route add default via 172.16.1.1

ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1

# 1470 + 28 (ICMP+IP) = 1498, just above the effective MTU
output=$(ip netns exec n0 ping -c1 -W2 -s1470 -M do -n 10.0.1.1 2>&1 || true)
echo "$output"
echo "$output" | grep -qi "frag needed\|message too big\|mtu\|unreachable" \
	|| fail "expected ICMP Frag Needed for oversized DF packet, got: $output"
