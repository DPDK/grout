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

ping6 -i0.1 -c10 -n fd00:ba4:0::2
ping6 -i0.01 -c3 -n fd00:ba4:1::2

# Expect these to fail
grcli route get fd00:baa::1 && fail "unknown destination resolved"
ping6 -c1 -W1 -n fd00:ba4:1::3 && fail "ping to non-existent host succeeded"

traceroute -N1 -n fd00:ba4:1::2
