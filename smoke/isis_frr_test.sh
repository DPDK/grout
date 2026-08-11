#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# Test ISIS adjacency between grout+FRR and a pure FRR peer with jumbo MTU.
#
# ISIS hello packets are padded to the interface MTU. With jumbo frames
# (MTU > 1500), the 802.3/LLC length field overflows and the kernel uses
# ether type 0x8870 (Jumbo LLC) instead. Grout must handle these frames
# and deliver them to FRR for the adjacency to form.
#
# See: https://github.com/DPDK/grout/issues/689
#
#                                                          .----------------------.
#                                                          |   netns "isis-peer"   |
#  .--------..------------.                                |        .-------.      |
#  | zebra  ||   grout    |                                |        | isisd |      |
#  '--------'|            |                                |        '-------'      |
#  .-------. |    .-----------------.             .----------------. .-------.     |
#  | isisd | |    |       p0        |   net_tap   |      x-p0     | | zebra |     |
#  '-------' |    |                 +-------------+                | '-------'     |
#          .----. | 198.51.100.1/24 |             | 198.51.100.2/24|.------------. |
#          |main| '-----------------'             '----------------'|     lo     | |
#          '----'     mtu 9000                       mtu 9000      |            | |
#            |  ping <------------------------------------------->  |203.0.113.1| |
#            |          |                                |          '------------' |
#            '----------'                                '------------------------'

grout_max_mtu=9000

. $(dirname $0)/_init_frr.sh

create_interface p0 mtu 9000
set_ip_address p0 198.51.100.1/24

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal
!
ip router-id 198.51.100.1
!
interface p0
	ip router isis smoke
	isis network point-to-point
exit
!
router isis smoke
	net 49.0000.0000.0001.00
	redistribute ipv4 static level-1
	redistribute ipv4 static level-2
exit
!
EOF

start_frr isis-peer 0
ip link set x-p0 mtu 9000
move_to_netns x-p0 isis-peer

# Configure FRR ISIS peer router
vtysh -N isis-peer <<-EOF
configure terminal
!
ip router-id 198.51.100.2
!
interface lo
	ip address 203.0.113.1/32
exit
!
interface x-p0
	ip address 198.51.100.2/24
	ip router isis smoke
	isis network point-to-point
exit
!
router isis smoke
	net 49.0000.0000.0002.00
	redistribute ipv4 connected level-1
exit
!
EOF

# Wait for ISIS neighbor adjacency
attempts=30
while ! vtysh -c 'show isis neighbor json' | jq -e '.areas[0].circuits[0].state == "Up"' ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		vtysh -c 'show isis neighbor'
		vtysh -N isis-peer -c 'show isis neighbor'
		fail "ISIS failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

# Wait for ISIS route exchange
wait_event -t 90 'route4 add: vrf=main 203.0.113.1/32 origin=isis'

grcli ping 203.0.113.1 count 3 delay 10
