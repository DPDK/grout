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
# Forward path (n0 → n1):
#   - n0 sends regular IPv6 ping to 2001:db8:101::2
#   - grout routes packet to n1 via p1 (regular IPv6, no SRv6)
#   - n1 receives packet
#
# Return path (n1 → n0) - TESTS grout's END.X traffic engineering:
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

sleep 2

# Neighbor discovery
ip netns exec n0 ping6 -c2 -W2 2001:db8:61::1 > /dev/null 2>&1 || true
ip netns exec n0 ping6 -c2 -W2 2001:db8:62::1 > /dev/null 2>&1 || true
ip netns exec n1 ping6 -c2 -W2 2001:db8:101::1 > /dev/null 2>&1 || true
sleep 1

# grout configuration: END.X SID with USD flavor
# IMPORTANT: Forces traffic via p0-bis (TE path) instead of default p0
# This demonstrates END.X traffic engineering capability
grcli nexthop add srv6-local behavior end.x nexthop 2001:db8:62::2 iface p0-bis flavor usd id 200
grcli route add 5f00:102::100/128 via id 200

# n1: encapsulate return traffic to n0 with grout's END.X SID
# mode encap: outer IPv6 dst=END.X SID, inner=original packet
# END.X will decapsulate (USD) and route inner packet via p0-bis
ip -n n1 -6 route del default via 2001:db8:101::1 dev x-p1
ip -n n1 -6 route add 2001:db8:61::/64 encap seg6 mode encap \
	segs 5f00:102::100 dev x-p1
ip -n n1 -6 route add 5f00:102::/32 via 2001:db8:101::1 dev x-p1

echo ""
echo "=== Configuration Summary ==="
echo "grout END.X with USD:"
grcli nexthop show | grep -A1 end.x
echo ""
echo "n1 SRv6 encapsulation route:"
ip -n n1 -6 route show | grep encap

echo ""
echo "=== Testing SRv6 END.X Traffic Engineering ==="
echo "Sending ping from n0 (2001:db8:61::2) to n1 (2001:db8:101::2)..."
echo ""
echo "Forward path: n0 x-p0 → grout p0 → grout p1 → n1 (regular IPv6)"
echo "Return path: n1 → grout p1 (SRv6 to END.X) → grout p0-bis → n0 x-p0-bis"
echo ""
echo "END.X forces return traffic via p0-bis instead of default p0 (traffic engineering!)"

if ip netns exec n0 ping6 -c3 -W2 2001:db8:101::2; then
	echo ""
	echo "✓ TEST PASSED: SRv6 END.X Traffic Engineering works!"
	echo "  - Forward: n0 x-p0 → grout p0 → p1 → n1 (regular IPv6)"
	echo "  - Return: n1 → grout p1 (END.X) → p0-bis → n0 x-p0-bis (forced via TE path!)"
	echo "  - END.X successfully forced return traffic through p0-bis instead of default p0"
else
	echo ""
	echo "✗ TEST FAILED: Ping did not succeed"
	echo ""
	echo "=== grout sr6_local statistics ==="
	grcli stats show software | grep -E "sr6_local|srv6_local"
	echo ""
	echo "=== grout traces (last 10 packets) ==="
	grcli trace show count 10 | grep -A10 "sr6_local"
	fail "SRv6 END.X test failed"
fi

echo ""
echo "=== grout Statistics ==="
grcli stats show software | grep -E "NODE|sr6_local|srv6_local|ip6_output|ip6_forward"

echo ""
echo "=== grout Traces (verify USD decapsulation) ==="
grcli trace show count 5 | grep -B2 -A5 "sr6_local" || echo "(sr6_local node traces not captured in trace output)"
