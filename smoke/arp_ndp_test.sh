#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

# grout replies to ARP requests and neighbor solicitations following the strong
# host model: an address is only answered on the interface that owns it, unless
# it is explicitly exposed on other interfaces. When an interface MAC changes,
# the new MAC is used in subsequent replies.

reply() {
	local ns="$1" mac="$2"
	shift 2
	ip netns exec "$ns" "$@" | tee $tmp/reply || fail "$* got no reply"
	grep -iq "$mac" $tmp/reply || fail "$* reply did not contain mac $mac"
}

no_reply() {
	local ns="$1"
	shift
	if ip netns exec "$ns" "$@"; then
		fail "$* unexpectedly got a reply"
	fi
}

mac0=ba:d0:ca:ca:00:01
mac1=ba:d0:ca:ca:00:02
port_add p0 mac $mac0 vrf main
port_add p1 mac $mac1 vrf main

grcli address add 192.168.0.1/24 iface p0
grcli address add fd00:1::1/64 iface p0
grcli address add 192.168.1.1/24 iface p1
grcli address add fd00:2::1/64 iface p1

# The loopback address is only exposed on p0.
grcli address add 10.99.0.1/32 iface main
grcli address add fd00:99::1/128 iface main
grcli address expose 10.99.0.1/32 iface p0
grcli address expose fd00:99::1/128 iface p0

# This one is exposed on both p0 and p1.
grcli address add 10.99.0.2/32 iface main
grcli address add fd00:99::2/128 iface main
grcli address expose 10.99.0.2/32 iface p0
grcli address expose 10.99.0.2/32 iface p1
grcli address expose fd00:99::2/128 iface p0
grcli address expose fd00:99::2/128 iface p1

# The exposure targets are reported when listing addresses.
grcli address show | grep -E "10.99.0.1/32\s+p0$" || fail "10.99.0.1 not exposed on p0"
grcli address show | grep -E "10.99.0.2/32\s+p0,p1$" || fail "10.99.0.2 not exposed on p0,p1"

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 192.168.0.2/24 dev x-p0
ip -n n0 -6 addr add fd00:1::2/64 dev x-p0

netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 192.168.1.2/24 dev x-p1
ip -n n1 -6 addr add fd00:2::2/64 dev x-p1

# An interface answers for its own addresses.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0

# The loopback exposed on p0 is answered there.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::1 x-p0

# The loopback exposed on both ports is answered on p0 and p1.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.2
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::2 x-p0
reply n1 $mac1 arping -c1 -I x-p1 -s 192.168.1.2 10.99.0.2
reply n1 $mac1 ndisc6 -1 -r1 -s fd00:2::2 fd00:99::2 x-p1

# Strong host: p1 does not answer for an address owned by p0.
no_reply n1 arping -c1 -w1 -I x-p1 -s 192.168.1.2 192.168.0.1
no_reply n1 ndisc6 -1 -r1 -w1000 -s fd00:2::2 fd00:1::1 x-p1

# The loopback is not exposed on p1, so p1 does not answer for it.
no_reply n1 arping -c1 -w1 -I x-p1 -s 192.168.1.2 10.99.0.1
no_reply n1 ndisc6 -1 -r1 -w1000 -s fd00:2::2 fd00:99::1 x-p1

mark_events

# Changing the MAC in grout is reflected in ARP/NDP replies.
mac0=02:0f:00:0b:a4:01
grcli interface set port p0 mac $mac0

wait_event "nh update: type=L3 iface=p0 .*addr=192.168.0.1/24 state=reachable mac=$mac0"
wait_event "nh update: type=L3 iface=p0 .*addr=fd00:1::1/64 state=reachable mac=$mac0"

# The MAC change is mirrored on the linux tap interface. Revert back to the
# stable MAC set at creation by port_add.
ip -n n0 link set x-p0 address $(stable_mac p0)

reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::1 x-p0
