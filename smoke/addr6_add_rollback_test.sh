#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy

# Verify that a refused IPv6 address add leaves no state behind.
#
# Adding fd00:1::9/64 on p0 fails because the connected route fd00:1::/64 is
# already owned by fd00:1::1/64. When the route insertion fails, the nexthop
# created for the address and the solicited-node multicast group joined for it
# must be released, otherwise grout answers neighbor solicitations for an
# address it cannot route, and the address can never be configured again.

. $(dirname $0)/_init.sh

port_add p0
grcli address add fd00:1::1/64 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add fd00:1::2/64 dev x-p0

grcli address add fd00:1::9/64 iface p0 && fail "colliding prefix should be refused"

# grout must not reply to neighbor solicitations for the refused address.
ip netns exec n0 timeout 5 tcpdump -tlpnn -i x-p0 \
	'src fd00:1::9 and icmp6 and ip6[40] == 136' > $tmp/na.txt 2>&1 &
tcpdump_pid=$!
sleep 1
ip -n n0 -6 neigh flush all
ip netns exec n0 ping -6 -i0.2 -c3 -W1 -n fd00:1::9 && fail "refused address should not be reachable"
wait $tcpdump_pid || true
cat $tmp/na.txt
if grep -q 'neighbor advertisement' $tmp/na.txt; then
	fail "grout answered NS for fd00:1::9 although the add was refused"
fi

# The refused address must still be configurable with a valid prefix length.
grcli address add fd00:1::9/128 iface p0 || fail "address add after a refused add failed"
grcli -j address show iface p0 | jq -e '.[] | select(.address == "fd00:1::9/128")' ||
	fail "fd00:1::9/128 not listed after a successful add"

ip -n n0 -6 neigh flush all
ip netns exec n0 ping -6 -i0.01 -c3 -W1 -n fd00:1::9 || fail "ping to fd00:1::9 failed"
