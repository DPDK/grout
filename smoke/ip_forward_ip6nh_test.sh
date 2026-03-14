#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0
port_add p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 16.$n.0.1/32 dev lo
	ip -n $ns route add 16.$((n^1)).0.0/16 via inet6 $(llocal_addr p$n) dev $p
	# use link-local addresses of peers as IPv6 nexthops for MAC resolution
	ll=$(ip -j -n $ns -6 addr show dev $p scope link | jq -er '.[0].addr_info[] | select(.scope == "link") | .local')
	grcli nexthop add l3 iface p$n address $ll id $((n+42))
	grcli route add 16.$n.0.0/16 via id $((n+42))
done

sleep 3  # wait for DAD

for n in 0 1; do
	ns=n$n
	ip netns exec $ns ping -i0.01 -c3 -n 16.$((n^1)).0.1
	mac=$(ip -j -n $ns link show x-p$n | jq -er '.[0].address')
	grcli -j nexthop show | jq -e --argjson id $((n+42)) --arg mac "$mac" \
		'.[] | select(.id == $id and (.info | contains($mac)))'
done
