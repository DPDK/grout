#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

# Routes and group memberships of deleted nexthops and interfaces.

. $(dirname $0)/_init.sh

grcli interface add vrf v1
port_add p0
port_add p1
port_add p2 vrf v1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli address add fd00:1::1/64 iface p1
grcli address add 172.16.2.1/24 iface p2

grcli nexthop add l3 iface p0 id 10 address 172.16.0.2 mac 02:00:00:00:00:02
grcli nexthop add l3 iface p1 id 11 address 172.16.1.2 mac 02:00:00:00:01:02
grcli nexthop add l3 iface p1 id 12 address 172.16.1.3 mac 02:00:00:00:01:03
grcli nexthop add l3 iface p1 id 13 address 172.16.1.4 mac 02:00:00:00:01:04
grcli nexthop add l3 iface p1 id 14 address 172.16.1.5 mac 02:00:00:00:01:05
grcli nexthop add l3 iface p1 id 16 address fd00:1::2 mac 02:00:00:00:01:02
grcli nexthop add group id 20 member 10 member 11
grcli nexthop add group id 21 member 12
grcli nexthop add group id 22 member 10 member 13 member 14

grcli route add 10.0.0.0/24 via id 10
grcli route add 10.1.0.0/24 via id 11
# The same nexthop is used from another VRF.
grcli route add 10.1.0.0/24 via id 11 vrf v1
grcli route add 10.2.0.0/24 via id 12
grcli route add 10.20.0.0/24 via id 20
grcli route add 10.21.0.0/24 via id 21
grcli route add 10.22.0.0/24 via id 22
grcli route add fd00:16::/64 via id 16

has_route() {
	grcli route show vrf "${2:-main}" | grep -qwF -e "$1"
}

has_nexthop() {
	grcli -j nexthop show | jq -e --argjson id "$1" '.[] | select(.id == $id)' > /dev/null
}

# members GROUP
members() {
	grcli -j nexthop show id "$1" | jq -c '[.members[].id] | sort'
}

check_members() {
	local m
	m=$(members "$1")
	[ "$m" = "$2" ] || fail "group $1 has members $m, expected $2"
}

grcli nexthop show
grcli route show
check_members 20 '[10,11]'
check_members 21 '[12]'
check_members 22 '[10,13,14]'

# A nexthop which no route and no group references.
grcli nexthop add l3 iface p1 id 15 address 172.16.1.6 mac 02:00:00:00:01:06
grcli nexthop del 15
has_nexthop 15 && fail "nexthop 15 still present"

# A nexthop whose routes were deleted before it.
grcli route del 10.2.0.0/24
grcli nexthop del 12
has_nexthop 12 && fail "nexthop 12 still present"
# It was the only member of a group.
check_members 21 '[]'

# A nexthop which is referenced by routes of two VRFs and by a group.
grcli nexthop del 11
has_nexthop 11 && fail "nexthop 11 still present"
has_route 10.1.0.0/24 && fail "route via nexthop 11 still present"
has_route 10.1.0.0/24 v1 && fail "route via nexthop 11 still present in v1"
check_members 20 '[10]'
# Nothing else was touched.
has_route 10.0.0.0/24 || fail "route via nexthop 10 deleted"
has_route 10.20.0.0/24 || fail "route via group 20 deleted"
has_route 10.22.0.0/24 || fail "route via group 22 deleted"
has_route 172.16.2.0/24 v1 || fail "connected route of v1 deleted"

# The nexthops of an interface which is removed.
grcli route add 10.3.0.0/24 via id 13
grcli route add 10.3.0.0/24 via id 13 vrf v1
grcli route add 10.4.0.0/24 via id 14
grcli interface del p1
for id in 13 14 16; do
	has_nexthop $id && fail "nexthop $id still present"
done
has_route 10.3.0.0/24 && fail "route via nexthop 13 still present"
has_route 10.3.0.0/24 v1 && fail "route via nexthop 13 still present in v1"
has_route 10.4.0.0/24 && fail "route via nexthop 14 still present"
has_route fd00:16::/64 && fail "route via nexthop 16 still present"
has_route 172.16.1.0/24 && fail "connected route of p1 still present"
check_members 22 '[10]'
# The other interfaces are not affected.
has_nexthop 10 || fail "nexthop 10 deleted"
has_route 10.0.0.0/24 || fail "route via nexthop 10 deleted"
has_route 10.20.0.0/24 || fail "route via group 20 deleted"
has_route 10.22.0.0/24 || fail "route via group 22 deleted"
has_route 172.16.0.0/24 || fail "connected route of p0 deleted"
has_route 172.16.2.0/24 v1 || fail "connected route of v1 deleted"

# The groups can still be used and deleted.
grcli nexthop add group id 20 member 10
grcli nexthop del 22
grcli nexthop del 21
grcli nexthop del 20
grcli nexthop del 10
has_route 10.0.0.0/24 && fail "route via nexthop 10 still present"
grcli nexthop show
grcli route show
