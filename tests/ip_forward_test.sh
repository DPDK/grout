#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=brtap0
p1=brtap1

br-cli -xe <<EOF
add interface port $p0 devargs net_tap0,iface=$p0
add interface port $p1 devargs net_tap1,iface=$p1
add ip address 10.0.0.1/24 iface $p0
add ip address 10.1.0.1/24 iface $p1
EOF

for n in 0 1; do
	ip netns add brns$n
	echo ip netns del brns$n >> $tmp/cleanup
	ip link set brtap$n netns brns$n
	ip -n brns$n link set brtap$n up
	ip -n brns$n addr add 10.$n.0.2/24 dev brtap$n
	ip -n brns$n route add default via 10.$n.0.1
done

ip netns exec brns0 ping -c3 10.1.0.2
ip netns exec brns1 ping -c3 10.0.0.2
