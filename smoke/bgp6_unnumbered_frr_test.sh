#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

# Test BGP unnumbered (RFC 5549) between an FRR+Grout setup and a pure
# FRR BGP peer. BGP unnumbered relies on IPv6 Router Advertisements to
# discover the peer's link-local address. This test verifies that
# received RAs are properly punted to the control plane TAP device.
#
#                                                     .-------------------.
#                                                     |  netns "bgp-peer" |
#  .-------..-------------.                           |        .------.   |
#  | zebra ||    grout    |                           |        | bgpd |   |
#  '-------'|             |                           |        '------'   |
#  .------. |       .------------.             .------------. .-------.   |
#  | bgpd | |       |     p0     |   net_tap   |    x-p0    | | zebra |   |
#  '------' |       |            +-------------+            | '-------'   |
#         .------.  | link-local |             | link-local |.----------. |
#         | main |  '------------'             '------------'|    lo    | |
#         '------'        |                           |      |          | |
#            |            |                           |      | fd00::1 | |
#            |            |                           |      '----------' |
#            '------------'                           '-------------------'

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

# Configure FRR BGP peer with unnumbered
vtysh -N bgp-peer <<-EOF
configure terminal

interface lo
	ipv6 address fd00::1/128
exit

router bgp 64513
	bgp router-id 10.0.0.2
	no bgp ebgp-requires-policy

	neighbor x-p0 interface remote-as external

	address-family ipv6 unicast
		neighbor x-p0 activate
		network fd00::1/128
	exit-address-family
exit
EOF

mark_events

# Configure Grout FRR instance with BGP unnumbered
vtysh <<-EOF
configure terminal

router bgp 64512
	bgp router-id 10.0.0.1
	no bgp ebgp-requires-policy

	neighbor p0 interface remote-as external

	address-family ipv6 unicast
		neighbor p0 activate
	exit-address-family
exit
EOF

# Wait for BGP route from the peer. This proves that:
# 1. The peer's RAs were received by grout and punted to the TAP
# 2. FRR learned the peer's link-local from the RA
# 3. The BGP unnumbered session was established
# 4. Routes were successfully exchanged
wait_event -t 30 'route6 add: vrf=main fd00::1/128 origin=bgp'
