#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christopher Dziomba

# This test checks BGP unnumbered (RFC 5549) peering between an FRR+grout setup
# and a pure FRR BGP peer. Unnumbered peering relies on IPv6 Router
# Advertisements to discover the peer link-local next hop. grout must punt the
# RAs it receives on a port to that port's control plane so the FRR instance
# running on top of grout can consume them; otherwise the session never leaves
# the Idle state.
#
# Both routers only advertise an IPv4 loopback prefix. The resulting IPv4
# routes are installed with an IPv6 link-local next hop, which is what the
# final loopback to loopback ping exercises.
#
#   grout (zebra + bgpd)                          netns "bgp-peer" (frr)
#  .----------------------.                      .----------------------.
#  |  main                |                      |                  lo  |
#  |  192.0.2.1           |                      |         198.51.100.1 |
#  |         .------------|       net_tap        |------------.         |
#  |         |     p0     +----------------------+    x-p0    |         |
#  |         | unnumbered |  (IPv6 link-local)   | unnumbered |         |
#  '---------'------------'                      '------------'---------'
#
#   ping: 198.51.100.1 -> 192.0.2.1  (IPv4 route with an IPv6 next hop)

. $(dirname $0)/_init_frr.sh

create_interface p0

start_frr bgp-peer 0
ip link set x-p0 netns bgp-peer
ip -n bgp-peer link set x-p0 up

SECONDS=0
while ! ip -n bgp-peer link show x-p0 | grep -qw LOWER_UP; do
	if [ "$SECONDS" -gt 5 ]; then
		fail "x-p0 link was not LOWER_UP after 5 seconds"
	fi
	sleep 0.2
done

# Configure FRR BGP peer router (unnumbered eBGP over the interface).
vtysh -N bgp-peer <<-EOF
configure terminal

interface lo
	ip address 198.51.100.1/32
exit

router bgp 64512
	bgp router-id 198.51.100.1
	no bgp ebgp-requires-policy

	neighbor x-p0 interface remote-as external

	address-family ipv4 unicast
		neighbor x-p0 activate
		network 198.51.100.1/32
	exit-address-family
exit
EOF

grcli address add 192.0.2.1/32 iface main

mark_events

# Configure grout FRR instance (unnumbered eBGP over the interface).
vtysh <<-EOF
configure terminal

router bgp 64513
	bgp router-id 192.0.2.1
	no bgp ebgp-requires-policy

	neighbor p0 interface remote-as external

	address-family ipv4 unicast
		neighbor p0 activate
		network 192.0.2.1/32
	exit-address-family
exit
EOF

# The route can only be learned once the unnumbered session is established,
# which requires grout to have punted the peer's router advertisement.
wait_event -t 30 'route4 add: vrf=main 198.51.100.1/32 origin=bgp'

# Wait for the reverse advertisement to be installed by the peer as well.
SECONDS=0
while ! ip -n bgp-peer route get 192.0.2.1 >/dev/null 2>&1; do
	if [ "$SECONDS" -gt 30 ]; then
		fail "bgp-peer did not learn 192.0.2.1 after 30 seconds"
	fi
	sleep 0.2
done

# Forward IPv4 traffic between both loopbacks over the IPv6 link-local next hop.
ip netns exec bgp-peer ping -i0.01 -c3 -n -I 198.51.100.1 192.0.2.1
