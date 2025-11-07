#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Andrea Panattoni

# This test leverages the following architecture to test the BGP route exchange
# between an FRR+Grout setup and a pure FRR BGP peer. At the end of the
# configuration phase, grout must be able to ping the loopback interface in the
# "bgp-peer" namespace since grout has learned the BGP route.
#
#                                                       .-------------------.
#                                                       |  netns "bgp-peer" |
#  .-------..-------------.                             |        .------.   |
#  | zebra ||    grout    |                             |        | bgpd |   |
#  '-------'|             |                             |        '------'   |
#  .------. |       .------------.               .------------. .-------.   |
#  | bgpd | |       |     p0     |    net_tap    |    x-p0    | | zebra |   |
#  '------' |       |            +---------------+            | '-------'   |
#      .----------. | 172.16.0.1 |               | 172.16.0.2 |.----------. |
#      | gr-loop0 | '------------'               '------------'|    lo    | |
#      '----------'       |                             |      |          | |
#           |      ping <------------------------------------> | 16.0.0.1 | |
#           |             |                             |      '----------' |
#           '-------------'                             '-------------------'

. $(dirname $0)/_init_frr.sh

create_interface p0

set_ip_address p0 172.16.0.1/24

start_frr_on_namespace bgp-peer
ip link set x-p0 netns bgp-peer

# Configure FRR BGP peer router
vtysh -N bgp-peer <<-EOF
configure terminal

interface x-p0
	ip address 172.16.0.2/24
exit

interface lo
	ip address 16.0.0.1/24
exit

router bgp 64512
	bgp router-id 172.16.0.2

	neighbor 172.16.0.1 remote-as 64512

	address-family ipv4 unicast
		network 172.16.0.0/24
		network 16.0.0.0/24
	exit-address-family
exit
EOF

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal

router bgp 64512
	bgp router-id 172.16.0.1

	neighbor 172.16.0.2 remote-as 64512
	neighbor 172.16.0.2 update-source 172.16.0.1

	address-family ipv4 unicast
		network 172.16.0.0/24
	exit-address-family
exit
EOF

# Wait for BGP routes to be exchanged
attempts=0
while ! grcli route show | grep -qE '16.0.0.0/24[[:space:]]+\<bgp\>'; do
	if [ "$attempts" -ge 40 ]; then
		fail "BGP route not learned in Grout"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

grcli ping 16.0.0.1 count 3 delay 10
