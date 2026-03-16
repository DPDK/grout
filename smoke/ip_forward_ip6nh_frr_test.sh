#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init_frr.sh

create_interface p0
create_interface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 16.$n.0.1/32 dev lo
	ip -n $ns route add 16.$((n^1)).0.0/16 via inet6 $(llocal_addr p$n) dev $p

	# configure cross-family static routes via FRR (IPv4 routes with IPv6 nexthops)
	ll=$(ip -j -n $ns -6 addr show dev x-p$n scope link |
		jq -er '.[0].addr_info[] | select(.scope == "link") | .local')

	set_ip_route 16.$n.0.0/16 "$ll p$n"
done

sleep 3  # wait for DAD

for n in 0 1; do
	ns=n$n
	ip netns exec $ns ping -i0.01 -c3 -n 16.$((n^1)).0.1
	ll=$(ip -j -n $ns -6 addr show dev x-p$n scope link |
		jq -er '.[0].addr_info[] | select(.scope == "link") | .local')
	mac=$(ip -j -n $ns link show x-p$n | jq -er '.[0].address')
	grcli -j nexthop show | jq -e --arg ll "$ll"  --arg mac "$mac" \
		'.[] | select(.origin == "zebra" and (.info | contains($ll) and contains($mac)))'
done
