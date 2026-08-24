#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

# grout and zebra must agree on the routes of an interface whose addresses
# are deleted.
#
# The addresses and routes are configured with grcli on purpose: an address
# configured in FRR keeps its connected entry flagged ZEBRA_IFC_CONFIGURED,
# and zebra would not consider the interface address-less.

. $(dirname $0)/_init_frr.sh

prefix4=203.0.113.0/24
prefix6=2001:db8:beef::/64
gw4=192.168.100.2
gw6=fd00:ba4::2

# assert_agree <prefix> <expected: yes|no> <context>
#
# Check that grout and zebra hold the same view of <prefix>, and that this
# view is the expected one. Retries to let the notification propagate.
assert_agree() {
	local prefix="$1"
	local expected="$2"
	local ctx="$3"
	local show="show ip route"
	local in_grout in_zebra tries=20

	[ "${prefix#*:}" != "$prefix" ] && show="show ipv6 route"

	while [ "$tries" -gt 0 ]; do
		in_grout=no
		in_zebra=no
		if grcli -j route show | jq -e \
			".[] | select(.destination == \"$prefix\")" >/dev/null 2>&1; then
			in_grout=yes
		fi
		if vtysh -c "$show $prefix" 2>/dev/null | grep -qE 'Known via "kernel"'; then
			in_zebra=yes
		fi
		[ "$in_grout" = "$expected" ] && [ "$in_zebra" = "$expected" ] && break
		tries=$((tries - 1))
		sleep 0.2
	done

	[ "$in_grout" = "$in_zebra" ] ||
		fail "$prefix $ctx: grout=$in_grout zebra=$in_zebra, tables disagree"
	[ "$in_grout" = "$expected" ] ||
		fail "$prefix $ctx: grout=$in_grout zebra=$in_zebra, expected $expected"
}

create_interface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add $gw4/24 dev x-p0
ip -n n0 addr add $gw6/64 dev x-p0

# Addresses and routes owned by grout: zebra learns them through the
# plugin, so the connected entries are not flagged ZEBRA_IFC_CONFIGURED
# and really leave ifp->connected when deleted.
grcli address add 192.168.0.1/24 iface p0
grcli address add 192.168.100.1/24 iface p0
grcli address add fd00:f00::1/64 iface p0
grcli address add fd00:ba4::1/64 iface p0
grcli route add $prefix4 via $gw4
grcli route add $prefix6 via $gw6

assert_agree $prefix4 yes "after route add"
assert_agree $prefix6 yes "after route add"

# Deleting an address which is not the last one of its family changes
# nothing.
grcli address del 192.168.0.1/24 iface p0
grcli address del fd00:f00::1/64 iface p0

assert_agree $prefix4 yes "after deleting a non-last address"
assert_agree $prefix6 yes "after deleting a non-last address"

# Deleting the last IPv6 address keeps both routes: the interface still
# has its link-local address to source neighbor solicitations from.
grcli address del fd00:ba4::1/64 iface p0

assert_agree $prefix6 yes "after deleting the last IPv6 address"
assert_agree $prefix4 yes "after deleting the last IPv6 address"

# Deleting the last IPv4 address flushes the IPv4 routes of the
# interface, and only those.
grcli address del 192.168.100.1/24 iface p0

assert_agree $prefix4 no "after deleting the last IPv4 address"
assert_agree $prefix6 yes "after deleting the last IPv4 address"

true
