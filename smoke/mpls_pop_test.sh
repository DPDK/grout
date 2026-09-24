#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# MPLS nexthop: pop (no labels), forward via n1
grcli nexthop add mpls iface p1 via 172.16.1.2 id 42

# label route: incoming label 100 -> pop
grcli mpls route add 100 nexthop id 42

# return path (plain IP)
grcli route add 10.0.0.0/24 via 172.16.0.2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
done

# n0: push label 100 when sending to 10.0.1.0/24
ip netns exec n0 sysctl -wq net.mpls.platform_labels=1000
ip -n n0 addr add 10.0.0.1/32 dev lo
ip -n n0 route add 10.0.1.0/24 encap mpls 100 via 172.16.0.1 dev x-p0

# n1: plain IP receiver
ip -n n1 addr add 10.0.1.1/32 dev lo
ip -n n1 route add default via 172.16.1.1

# resolve ARP before MPLS test
ip netns exec n0 ping -c1 -n 172.16.0.1

# n0 pushes MPLS(100) -> grout pops label, propagates TTL -> n1 receives plain IP
ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1
