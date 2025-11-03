#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli route add 16.0.0.0/16 via 172.16.0.2
grcli nexthop add l3 iface p1 id 45
grcli route add 16.1.0.0/16 via id 45

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	ip link set $p netns $ns
	ip -n $ns link set $p up
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	if [[ $n -eq 0 ]]; then
		ip -n $ns addr add 16.$n.0.1/16 dev lo
	else
		ip -n $ns addr add 16.$n.0.1/16 dev $p
	fi
	ip -n $ns route add default via 172.16.$n.1
done

ip netns exec n0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec n1 ping -i0.01 -c3 -n 16.0.0.1
ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n1 ping -i0.01 -c3 -n 172.16.0.2
ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec n1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec n0 traceroute -N1 -n 16.1.0.1
ip netns exec n1 traceroute -N1 -n 16.0.0.1
ip netns exec n0 traceroute -N1 -n 172.16.1.2
ip netns exec n1 traceroute -N1 -n 172.16.0.2
