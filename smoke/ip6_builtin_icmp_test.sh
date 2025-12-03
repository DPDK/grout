#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add fd00:ba4:0::1/64 iface p0
grcli address add fd00:ba4:1::1/64 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add fd00:ba4:$n::2/64 dev $p
	ip -n $ns route add fd00:ba4::/62 via fd00:ba4:$n::1 dev $p
done

sleep 3  # wait for DAD

grcli ping6 fd00:ba4:0::2 count 10 delay 100
grcli ping6 fd00:ba4:1::2 count 3 delay 10

# Expect this test to fail
grcli ping6 fd00:baa::1 count 1 && fail "ping to unknown route succeeded"
grcli ping6 fd00:ba4:1::3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute6 fd00:ba4:1::2
