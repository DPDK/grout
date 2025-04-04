#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli add interface port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:13:00
grcli add interface port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:13:01
grcli add ip6 address fd00:ba4:0::1/64 iface $p0
grcli add ip6 address fd00:ba4:1::1/64 iface $p1

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:cd:00:0$n
	ip -n $p link set $p up
	ip -n $p addr add fd00:ba4:$n::2/64 dev $p
	ip -n $p route add fd00:ba4::/62 via fd00:ba4:$n::1 dev $p
	ip -n $p addr show
done

sleep 3  # wait for DAD

grcli ping fd00:ba4:0::2 count 10 delay 100
grcli ping fd00:ba4:1::2 count 3 delay 10

# Expect this test to fail
grcli ping fd00:baa::1 count 1 && fail "ping to unknown route succeeded"
grcli ping fd00:ba4:1::3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute fd00:ba4:1::2
