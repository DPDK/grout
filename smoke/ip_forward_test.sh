#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

for n in 0 1; do
	p=$run_id$n
	port_add $p 40$n
	grcli address add 172.16.$n.1/24 iface $p
	netns_add $p 40$n
	ip -n $p addr add 172.16.$n.2/24 dev $p
	if [[ $n -eq 0 ]]; then
		ip -n $p addr add 16.$n.0.1/16 dev lo
	else
		ip -n $p addr add 16.$n.0.1/16 dev $p
	fi
	ip -n $p route add default via 172.16.$n.1
done

grcli route add 16.0.0.0/16 via 172.16.0.2
grcli nexthop add l3 iface $p1 id 45
grcli route add 16.1.0.0/16 via id 45

ip netns exec $p0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec $p1 ping -i0.01 -c3 -n 16.0.0.1
ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2
ip netns exec $p0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec $p0 traceroute -N1 -n 16.1.0.1
ip netns exec $p1 traceroute -N1 -n 16.0.0.1
ip netns exec $p0 traceroute -N1 -n 172.16.1.2
ip netns exec $p1 traceroute -N1 -n 172.16.0.2
