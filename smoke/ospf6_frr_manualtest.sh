#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#                                                    .--------------------.
#                                                    | netns "ospf6-peer" |
#  .--------..------------.                          |        .--------.  |
#  | zebra  ||   grout    |                          |        | ospf6d |  |
#  '--------'|            |                          |        '--------'  |
#  .--------.|      .-----------.             .------------. .-------.    |
#  | ospf6d ||      |     p0    |   net_tap   |    x-p0    | | zebra |    |
#  '--------'|      |           +-------------+            | '-------'    |
#        .------.   | fe80::/64 |             | fe80::/64  |.----------.  |
#        | main |   '-----------'             '------------'|    lo    |  |
#        '------'       |                          |        |          |  |
#            |  ping <------------------------------------> |2001:db8: |  |
#            |          |                          |        |  1000::1 |  |
#            '----------'                          |        '----------'  |
#                                                  '----------------------'

. $(dirname $0)/_init_frr.sh

create_interface p0
set_ip_address p0 2001:db8::1/64

start_frr ospf6-peer 0
ip link set x-p0 netns ospf6-peer

ip -n grout l set p0 up
ip -n ospf6-peer l set x-p0 up

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal
ipv6 forwarding
!
#debug ospf6 event
#debug ospf6 message all
!
interface p0
	ipv6 ospf6 area 0.0.0.1
	ipv6 ospf6 hello-interval 1
	ipv6 ospf6 network point-to-point
exit
!
router ospf6
	ospf6 router-id 1.1.1.1
	area 0.0.0.1 range 2001:db8::/48
exit
!
EOF

vtysh -N ospf6-peer <<-EOF
configure terminal
ipv6 forwarding
!
#debug ospf6 event
#debug ospf6 message all
!
interface lo
	ipv6 address 2001:db8:1000::1/64
exit
!
interface x-p0
	ipv6 ospf6 area 0.0.0.1
	ipv6 ospf6 hello-interval 1
	ipv6 ospf6 network point-to-point
exit
!
router ospf6
	ospf6 router-id 2.2.2.2
	area 0.0.0.1 range 2001:db8::/48
	redistribute connected
exit
end
!
EOF

# Convergence takes ~40s, be patient.
attempts=60
while ! vtysh -c 'show ipv6 ospf6 neighbor json' | jq '.neighbors[] | select(.neighborId=="2.2.2.2") | .state == "Full"' -e ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF6 failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

attempts=30
while ! vtysh -c 'show ipv6 route ospf6 json' | jq '."2001:db8:1000::/64"[0].protocol == "ospf6"' -e ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF6 failed to get routes."
	fi
	attempts=$((attempts - 1))
done

grcli ping6 2001:db8:1000::1 count 3 delay 10
