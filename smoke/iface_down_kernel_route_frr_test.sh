#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

# grout and zebra must agree on the routes of an interface which goes
# administratively down, and both must leave them alone on carrier loss.
#
# The addresses and routes are configured with grcli on purpose, see
# addr_del_kernel_route_frr_test.sh.

. $(dirname $0)/_init_frr.sh

prefix4=203.0.113.0/24
prefix6=2001:db8:beef::/64
gw4=192.168.0.2
gw6=fd00:ba4::2

# assert_agree <prefix> <expected: yes|no> <context>
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

grcli address add 192.168.0.1/24 iface p0
grcli address add fd00:ba4::1/64 iface p0
grcli route add $prefix4 via $gw4
grcli route add $prefix6 via $gw6

# The plugin enables the flush when it connects to grout.
grcli -j interface config show | jq -e .flush_routes_on_iface_down ||
	fail "the plugin did not enable flush-routes-on-iface-down"

# The knob must also be reachable from the CLI, the plugin is not the only
# writer. Put it back on afterwards, the rest of the test needs the flush.
grcli interface config set flush-routes-on-iface-down off
grcli -j interface config show | jq -e '.flush_routes_on_iface_down == false' ||
	fail "interface config set off had no effect"
grcli interface config set flush-routes-on-iface-down on
grcli -j interface config show | jq -e '.flush_routes_on_iface_down == true' ||
	fail "interface config set on had no effect"

assert_agree $prefix4 yes "after route add"
assert_agree $prefix6 yes "after route add"

# Carrier loss only: the interface stays up, nothing is flushed.
ip -n n0 link set x-p0 down

assert_agree $prefix4 yes "after carrier loss"
assert_agree $prefix6 yes "after carrier loss"

ip -n n0 link set x-p0 up

# Administratively down: both families are flushed on both sides.
grcli interface set port p0 down

assert_agree $prefix4 no "after setting p0 down"
assert_agree $prefix6 no "after setting p0 down"

true
