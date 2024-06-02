#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

br-cli add interface port $p0 devargs net_tap0,iface=$p0
br-cli add interface port $p1 devargs net_tap1,iface=$p1
br-cli add ip address 172.16.0.1/24 iface $p0
br-cli add ip address 172.16.1.1/24 iface $p1

for n in 0 1; do
	p=$run_id$n
	ip netns add $p
	echo ip netns del $p >> $tmp/cleanup
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

ip netns exec $p0 ping -i0.01 -c3 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 172.16.0.2
