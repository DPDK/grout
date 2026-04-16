#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

# This test verifies that BFD sessions work over IPv6 between an FRR+Grout
# setup and a pure FRR BGP peer. This is a regression test for the /128
# prefix length issue where bfdd cannot send BFD packets via the port
# representor due to missing connected route.
#
#                                                     .--------------------.
#                                                     |  netns "bfd-peer"  |
#  .-------..-------------.                           |        .------.    |
#  | zebra ||    grout    |                           |        | bgpd |    |
#  '-------'|             |                           |        '------'    |
#  .------. |       .---------------.          .---------------. .-------.  |
#  | bgpd | |       |      p0      |  net_tap  |     x-p0     | | zebra |  |
#  '------' |       |               +----------+              | '-------'  |
#  .------. | .---. | fd00:10::1/64 |          | fd00:10::2/64 | .------.  |
#  | bfdd | | |   | '---------------'          '---------------' | bfdd |  |
#  '------' | |   |       |                           |          '------'  |
#           '-|   |-------'                            '--------------------'
#             | m |
#             | a |  BFD session (UDP 3784)
#             | i |  fd00:10::1 <--> fd00:10::2
#             | n |
#             '---'

. $(dirname $0)/_init_frr.sh

create_interface p0

set_ip_address p0 fd00:10::1/64

start_frr bfd-peer 0
ip link set x-p0 netns bfd-peer

# Configure FRR peer with BGP + BFD over IPv6
vtysh -N bfd-peer <<-EOF
configure terminal

interface x-p0
	ipv6 address fd00:10::2/64
exit

router bgp 64512
	bgp router-id 10.0.0.2
	no bgp ebgp-requires-policy

	neighbor fd00:10::1 remote-as 64512
	neighbor fd00:10::1 passive
	neighbor fd00:10::1 bfd

	address-family ipv6 unicast
		neighbor fd00:10::1 activate
		network fd00:10::/64
	exit-address-family
exit
EOF

# Configure Grout FRR instance with BGP + BFD over IPv6
vtysh <<-EOF
configure terminal

router bgp 64512
	bgp router-id 10.0.0.1
	no bgp ebgp-requires-policy

	neighbor fd00:10::2 remote-as 64512
	neighbor fd00:10::2 update-source fd00:10::1
	neighbor fd00:10::2 timers connect 1
	neighbor fd00:10::2 bfd

	address-family ipv6 unicast
		neighbor fd00:10::2 activate
		network fd00:10::/64
	exit-address-family
exit
EOF

sleep 3  # wait for DAD

# Wait for BFD session to come up on the grout side
attempts=0
while ! vtysh -c "show bfd peers json" | jq -e '.[] | select(.status == "up")'; do
	if [ "$attempts" -ge 40 ]; then
		vtysh -c "show bfd peers"
		vtysh -c "show bfd peers counters"
		vtysh -c "show bgp ipv6 unicast summary"
		fail "BFD6 session did not come up on grout side"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

# Verify BFD session is also up on the peer side
attempts=0
while ! vtysh -N bfd-peer -c "show bfd peers json" | jq -e '.[] | select(.status == "up")'; do
	if [ "$attempts" -ge 20 ]; then
		vtysh -N bfd-peer -c "show bfd peers"
		fail "BFD6 session did not come up on peer side"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

# Verify BFD counters are non-zero (packets flowing)
input=$(vtysh -c "show bfd peers counters json" | jq '.[0]."control-packet-input"')
output=$(vtysh -c "show bfd peers counters json" | jq '.[0]."control-packet-output"')

if [ "$input" -eq 0 ] || [ "$output" -eq 0 ]; then
	vtysh -c "show bfd peers counters"
	fail "BFD6 counters are zero (input=$input output=$output)"
fi
