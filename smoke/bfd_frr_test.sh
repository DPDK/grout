#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

# This test verifies that BFD sessions work between an FRR+Grout setup and
# a pure FRR peer. BFD is configured on top of a BGP session. The test
# validates that the BFD session reaches the "up" state on both sides.
#
#                                                     .-------------------.
#                                                     |  netns "bfd-peer" |
#  .-------..-------------.                           |        .------.   |
#  | zebra ||    grout    |                           |        | bgpd |   |
#  '-------'|             |                           |        '------'   |
#  .------. |       .------------.             .------------. .-------.   |
#  | bgpd | |       |     p0     |   net_tap   |    x-p0    | | zebra |   |
#  '------' |       |            +-------------+            | '-------'   |
#  .------. | .---. | 172.16.0.1 |             | 172.16.0.2 | .------.   |
#  | bfdd | | |   | '------------'             '------------' | bfdd |   |
#  '------' | |   |      |                           |        '------'   |
#           '-|   |------'                            '-------------------'
#             | m |
#             | a |  BFD session (UDP 3784)
#             | i |  172.16.0.1 <--> 172.16.0.2
#             | n |
#             '---'

. $(dirname $0)/_init_frr.sh

create_interface p0

set_ip_address p0 172.16.0.1/24

start_frr bfd-peer 0
ip link set x-p0 netns bfd-peer

# Configure FRR peer with BGP + BFD
vtysh -N bfd-peer <<-EOF
configure terminal

interface x-p0
	ip address 172.16.0.2/24
exit

router bgp 64512
	bgp router-id 172.16.0.2

	neighbor 172.16.0.1 remote-as 64512
	neighbor 172.16.0.1 passive
	neighbor 172.16.0.1 bfd

	address-family ipv4 unicast
		network 172.16.0.0/24
	exit-address-family
exit
EOF

# Configure Grout FRR instance with BGP + BFD
vtysh <<-EOF
configure terminal

router bgp 64512
	bgp router-id 172.16.0.1

	neighbor 172.16.0.2 remote-as 64512
	neighbor 172.16.0.2 update-source 172.16.0.1
	neighbor 172.16.0.2 timers connect 1
	neighbor 172.16.0.2 bfd

	address-family ipv4 unicast
		network 172.16.0.0/24
	exit-address-family
exit
EOF


# Wait for BFD session to come up on the grout side
attempts=0
while ! vtysh -c "show bfd peers json" | jq -e '.[] | select(.status == "up")'; do
	if [ "$attempts" -ge 40 ]; then
		vtysh -c "show bfd peers"
		vtysh -c "show bfd peers counters"
		vtysh -c "show bgp summary"
		fail "BFD session did not come up on grout side"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

# Verify BFD session is also up on the peer side
attempts=0
while ! vtysh -N bfd-peer -c "show bfd peers json" | jq -e '.[] | select(.status == "up")'; do
	if [ "$attempts" -ge 20 ]; then
		vtysh -N bfd-peer -c "show bfd peers"
		fail "BFD session did not come up on peer side"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

# Verify BFD counters are non-zero (packets flowing)
input=$(vtysh -c "show bfd peers counters json" | jq '.[0]."control-packet-input"')
output=$(vtysh -c "show bfd peers counters json" | jq '.[0]."control-packet-output"')

if [ "$input" -eq 0 ] || [ "$output" -eq 0 ]; then
	vtysh -c "show bfd peers counters"
	fail "BFD counters are zero (input=$input output=$output)"
fi
