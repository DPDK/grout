#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#
#                                                     .--------------------.
#                                                     |  netns "isis-peer" |
#  .--------..------------.                           |       .-------.    |
#  | zebra  ||   grout    |                           |       | isisd |    |
#  '--------'|            |                           |       '-------'    |
#  .-------. |      .------------.             .------------. .-------.    |
#  | isisd | |      |     p0     |   net_tap   |    x-p0    | | zebra |    |
#  '-------' |      |            +-------------+            | '-------'    |
#          .------. | 172.16.0.1 |             | 172.16.0.2 |.----------.  |
#          | main | '------------'             '------------'|    lo    |  |
#          '------'       |                           |      |          |  |
#             |  ping <------------------------------------> | 16.0.0.1 |  |
#             |           |                           |      '----------'  |
#             '-----------'                           '--------------------'


. $(dirname $0)/_init_frr.sh

create_interface p0
set_ip_address p0 172.16.0.1/24

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal
!
ip router-id 172.16.0.1
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
ip link set x-p0 netns isis-peer

# Configure FRR ISIS peer router
vtysh -N isis-peer <<-EOF
configure terminal
!
ip router-id 172.16.0.2
!
interface lo
	ip address 16.0.0.1/32
exit
!
interface x-p0
	ip address 172.16.0.2/24
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

# Wait for ISIS peer neighbor
attempts=20
while ! vtysh -c 'show isis neighbor json' | jq -e '.areas[0].circuits[0].state == "Up"' ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "ISIS failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

# Wait for ISIS route exchange
attempts=90
while ! vtysh -c 'show ip route isis json' | jq -e '."16.0.0.1/32"' ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "ISIS failed to get routes."
	fi
	attempts=$((attempts - 1))
done

grcli ping 16.0.0.1 count 3 delay 10
