#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

p0a=${run_id}0a
p0b=${run_id}0b
p1a=${run_id}1a
p1b=${run_id}1b
bond0=${run_id}.bond0
bond1=${run_id}.bond1

grcli interface add port $p0a devargs net_tap0,iface=$p0a
grcli interface add port $p0b devargs net_tap1,iface=$p0b
grcli interface add port $p1a devargs net_tap2,iface=$p1a
grcli interface add port $p1b devargs net_tap3,iface=$p1b
grcli interface add bond $bond0 mode active-backup member $p0a member $p0b
grcli interface add bond $bond1 mode active-backup member $p1a member $p1b
grcli address add 172.16.0.1/24 iface $bond0
grcli address add 172.16.1.1/24 iface $bond1

for n in 0 1; do
	ns=${run_id}$n
	pa=${run_id}${n}a
	pb=${run_id}${n}b
	bond=$run_id.bond$n
	netns_add $ns

	ip link set $pa netns $ns
	ip link set $pb netns $ns
	ip -n $ns link add $bond type bond mode active-backup
	ip -n $ns link set $pa master $bond
	ip -n $ns link set $pb master $bond
	ip -n $ns link set $pa up
	ip -n $ns link set $pb up
	ip -n $ns link set $bond up
	ip -n $ns addr add 172.16.$n.2/24 dev $bond
	ip -n $ns route add default via 172.16.$n.1
	ip -n $ns addr show
done

ip netns exec ${run_id}0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec ${run_id}1 ping -i0.01 -c3 -n 172.16.0.2
