#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Harrison Caldicott

. $(dirname $0)/_init.sh

# Exercise both a standalone port and a bond with a native bridge and tagged
# subinterfaces. Tagged ingress must be resolved before native bridge learning.
for kind in port bond; do
	wire=${kind}wire
	parent=$wire
	for vid in 0 42 43; do
		grcli interface add bridge ${kind}br$vid
	done
	if [ "$kind" = bond ]; then
		parent=uplink
		grcli interface add bond $parent mode active-backup domain ${kind}br0
		port_add $wire domain $parent
	else
		port_add $wire domain ${kind}br0
	fi

	netns_add $wire
	move_to_netns x-$wire $wire
	ip -n $wire addr add 172.16.0.1/24 dev x-$wire
	for vid in 42 43; do
		grcli interface add vlan ${kind}v$vid parent $parent vlan_id $vid domain ${kind}br$vid
		ip -n $wire link add v$vid link x-$wire type vlan id $vid
		ip -n $wire link set v$vid up
		ip -n $wire addr add 172.16.$vid.1/24 dev v$vid
	done

	for vid in 0 42 43; do
		guest=${kind}g$vid
		port_add $guest domain ${kind}br$vid
		netns_add $guest
		move_to_netns x-$guest $guest
		ip -n $guest addr add 172.16.$vid.2/24 dev x-$guest
		ip netns exec $wire ping -i0.01 -c3 -W1 -n 172.16.$vid.2
		ip netns exec $guest ping -i0.01 -c3 -W1 -n 172.16.$vid.1

		# Each wire-side source must be learned on its own logical interface,
		# with the VLAN metadata consumed before reaching the bridge.
		iface=$parent
		[ "$vid" = 0 ] || iface=${kind}v$vid
		mac=$(ip netns exec $wire cat /sys/class/net/x-$wire/address)
		grcli -j fdb show iface $iface learn |
			jq -e --arg mac "$mac" '.[] | select(.mac == $mac and .vlan == 0)'
	done

	# An unknown tag must be dropped, not treated as native traffic. Give it
	# an address in the native subnet so an accidental native mapping replies.
	ip -n $wire link add v44 link x-$wire type vlan id 44
	ip -n $wire link set v44 address 02:00:00:00:44:01 up
	ip -n $wire addr add 172.16.0.3/24 dev v44
	grcli stats reset
	if ip netns exec $wire ping -I v44 -c1 -W1 -n 172.16.0.2; then
		fail "unknown VLAN reached the native bridge"
	fi
	grcli -j stats show software brief |
		jq -e '.iface_input_unknown_vlan > 0'
	if grcli -j fdb show learn | jq -e '.[] | select(.mac == "02:00:00:00:44:01")'; then
		fail "unknown VLAN source was learned in a bridge"
	fi
	# Remove the tagged source so its pending ARP retries cannot satisfy the
	# next drop counter check.
	ip -n $wire link del v44

	# Access ports do not own VLAN subinterfaces either. A tag matching the
	# uplink's configured VLAN must not escape through the native bridge.
	guest=${kind}g0
	ip -n $guest link add v42 link x-$guest type vlan id 42
	ip -n $guest link set v42 address 02:00:00:00:42:03 up
	ip -n $guest addr add 172.16.42.3/24 dev v42
	grcli stats reset
	if ip netns exec $guest ping -I v42 -c1 -W1 -n 172.16.42.1; then
		fail "tagged access traffic escaped through the native bridge"
	fi
	grcli -j stats show software brief |
		jq -e '.iface_input_unknown_vlan > 0'
	if grcli -j fdb show learn | jq -e '.[] | select(.mac == "02:00:00:00:42:03")'; then
		fail "tagged access source was learned in a bridge"
	fi
	ip -n $guest link del v42
done
