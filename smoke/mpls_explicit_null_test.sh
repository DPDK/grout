#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# IP route for the decapsulated packet (no MPLS nexthop needed)
grcli route add 10.0.1.0/24 via 172.16.1.2

# return path
grcli route add 10.0.0.0/24 via 172.16.0.2

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
done

# n0: push explicit null (label 0)
ip -n n0 addr add 10.0.0.1/32 dev lo
ip -n n0 route add 10.0.1.0/24 encap mpls 0 via 172.16.0.1 dev x-p0

# n1: plain IP receiver
ip -n n1 addr add 10.0.1.1/32 dev lo
ip -n n1 route add default via 172.16.1.1

# resolve ARP before MPLS test
ip netns exec n0 ping -c1 -n 172.16.0.1

# n0 pushes MPLS(label=0) -> grout strips and routes via ip_input -> n1 receives plain IP
ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1
