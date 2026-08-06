#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

#
# Test SRv6 END.X behavior (RFC 8986 Section 4.10)
# Tests grout's END.X traffic engineering capability
#
# network layout:
#  n0 (client)                    grout (END.X)                    n1 (server)
# 2001:db8:61::2  <--- p0 (default path)
#                      p0-bis (TE path) --->  x-p0-bis             2001:db8:101::2
#     |                          |          |                        |
#  x-p0 <------------------------+          +----------------------> x-p1
# 2001:db8:62::2 <--- x-p0-bis
#
# Forward path (n0 -> n1):
#   - n0 sends regular IPv6 ping to 2001:db8:101::2
#   - grout routes packet to n1 via p1 (regular IPv6, no SRv6)
#   - n1 receives packet
#
# Return path (n1 -> n0) - TESTS grout's END.X traffic engineering:
#   - n1 has SRv6 route to n0's network via grout's END.X SID
#   - n1 encapsulates reply: outer dst=5f00:102::100, inner=original packet
#   - grout receives at END.X SID 5f00:102::100 on p1
#   - END.X behavior: forces traffic through p0-bis instead of default p0
#   - END.X sets explicit nexthop 2001:db8:62::2 on p0-bis (traffic engineering!)
#   - USD flavor: decapsulate outer IPv6 header
#   - grout forwards inner packet to n0 via p0-bis (not the default p0)
#
# IPv6 address plan:
# - 2001:db8:61::/64  - Default path network (n0 x-p0 <-> grout p0)
# - 2001:db8:62::/64  - TE path network (n0 x-p0-bis <-> grout p0-bis)
# - 2001:db8:101::/64 - Server network (grout p1 <-> n1)
# - 5f00:102::100/128 - END.X SID on grout (forces traffic via p0-bis)
#

. $(dirname $0)/_init.sh

port_add p0
port_add p0-bis
port_add p1

grcli address add 2001:db8:61::1/64 iface p0
grcli address add 2001:db8:62::1/64 iface p0-bis
grcli address add 2001:db8:101::1/64 iface p1

# n0 namespace (client) - has two connections to grout
netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 2001:db8:61::2/64 dev x-p0
ip -n n0 -6 route add default via 2001:db8:61::1 dev x-p0

# Second interface for traffic engineering path
ip link set x-p0-bis netns n0
ip -n n0 link set x-p0-bis up
ip -n n0 addr add 2001:db8:62::2/64 dev x-p0-bis

# n1 namespace (server)
netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 2001:db8:101::2/64 dev x-p1
ip -n n1 -6 route add default via 2001:db8:101::1 dev x-p1

# grout configuration: END.X SID with USD flavor
# IMPORTANT: Forces traffic via p0-bis (TE path) instead of default p0
# This demonstrates END.X traffic engineering capability
# Test srv6-local nexthop add/update/del lifecycle
grcli nexthop add srv6-local behavior end.x nexthop 2001:db8:62::2 iface p0-bis flavor usd id 200
grcli -j nexthop show id 200 | jq -e 'select(.behavior == "end.x")' || fail "nh 200 should be end.x"

# Update in place (exist_ok): change nexthop address, then back
grcli nexthop add srv6-local behavior end.x nexthop 2001:db8:62::1 iface p0-bis flavor usd id 200
grcli -j nexthop show id 200 | jq -e 'select(.endx_addr == "2001:db8:62::1")' || fail "nh 200 endx_addr should be updated"

grcli nexthop add srv6-local behavior end.x nexthop 2001:db8:62::2 iface p0-bis flavor usd id 200
grcli -j nexthop show id 200 | jq -e 'select(.endx_addr == "2001:db8:62::2")' || fail "nh 200 endx_addr should be restored"

# Delete and re-create
grcli nexthop del 200
grcli nexthop show id 200 && fail "nh 200 should not exist after delete"
grcli nexthop add srv6-local behavior end.x nexthop 2001:db8:62::2 iface p0-bis flavor usd id 200

grcli route add 5f00:102::100/128 via id 200

# n1: encapsulate return traffic to n0 with grout's END.X SID
# mode encap: outer IPv6 dst=END.X SID, inner=original packet
# END.X will decapsulate (USD) and route inner packet via p0-bis
ip -n n1 -6 route del default via 2001:db8:101::1 dev x-p1
ip -n n1 -6 route add 2001:db8:61::/64 encap seg6 mode encap \
	segs 5f00:102::100 dev x-p1
ip -n n1 -6 route add 5f00:102::/32 via 2001:db8:101::1 dev x-p1

# Configuration Summary
grcli nexthop show | grep -A1 end.x
ip -n n1 -6 route show | grep encap

grcli trace clear

# Testing SRv6 END.X Traffic Engineering
# Sending ping from n0 (2001:db8:61::2) to n1 (2001:db8:101::2)
#
# Forward path: n0 x-p0 -> grout p0 -> grout p1 -> n1 (regular IPv6)
# Return path: n1 -> grout p1 (SRv6 to END.X) -> grout p0-bis -> n0 x-p0-bis
#
# END.X forces return traffic via p0-bis instead of default p0 (traffic engineering!)
if ! ip netns exec n0 ping6 -i0.01 -c3 -n 2001:db8:101::2; then
	grcli trace show count 20 | grep -B5 -A7 "sr6_local: action=end.x"
	fail "SRv6 END.X test failed"
fi

grcli trace show count 20 | grep -B5 -A7 "sr6_local: action=end.x"
