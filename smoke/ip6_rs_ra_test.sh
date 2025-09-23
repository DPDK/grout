#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

command -v rdisc6 || fail "rdisc6 (from ndisc6 package) is not installed"

p1=${run_id}1

grcli interface add port $p1 devargs net_tap0,iface=$p1 mac d2:f0:0c:ba:a4:11
grcli address6 add fd00:ba4:1::1/64 iface $p1

for n in 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address d2:ad:ca:ca:a4:1$n
	ip -n $p link set $p up
	ip -n $p addr add fd00:ba4:$n::2/64 dev $p
	ip -n $p addr show
done

sleep 3  # wait for DAD

ip netns exec $p1 rdisc6 -n $p1
