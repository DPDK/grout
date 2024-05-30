#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=$(name 0)
p1=$(name 1)

br-cli -xe <<EOF
add interface port $p0 devargs net_tap0,iface=$p0
add interface port $p1 devargs net_tap1,iface=$p1
add ip address 10.0.0.1/24 iface $p0
add ip address 10.1.0.1/24 iface $p1
EOF

for n in 0 1; do
	p=$(name $n)
	ip netns add $p
	echo ip netns del $p >> $tmp/cleanup
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 10.$n.0.2/24 dev $p
	ip -n $p route add default via 10.$n.0.1
done

ip netns exec $p0 ping -i0.01 -c3 10.1.0.2
ip netns exec $p1 ping -i0.01 -c3 10.0.0.2
