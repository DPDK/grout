#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# MPLS nexthop: push two labels (outer=200 inner=100), forward via n1
grcli nexthop add mpls iface p1 via 172.16.1.2 labels 200 100 id 42

# IP route pointing to multi-label MPLS nexthop
grcli route add 10.0.1.0/24 via id 42

# return path (plain IP)
grcli route add 10.0.0.0/24 via 172.16.0.2

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

# n1: MPLS receiver, pop outer label 200 then inner label 100
ip netns exec n1 sysctl -wq net.mpls.platform_labels=1000
ip netns exec n1 sysctl -wq net.mpls.conf.x-p1.input=1
ip netns exec n1 sysctl -wq net.mpls.conf.lo.input=1
ip -n n1 addr add 10.0.1.1/32 dev lo
# pop outer 200 via lo (recirculates as [100,IP] to lo), then pop inner 100
ip -n n1 -f mpls route add 200 dev lo
ip -n n1 -f mpls route add 100 dev lo

# return path from n1
ip -n n1 route add default via 172.16.1.1

# plain IP -> grout pushes MPLS(200,100) -> n1 pops both labels
ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1
