#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#                                                       .--------------------.
#                                                       |  netns "ospf-peer" |
#  .--------..------------.                             |        .-------.   |
#  | zebra  ||   grout    |                             |        | ospfd |   |
#  '--------'|            |                             |        '-------'   |
#  .-------. |      .------------.               .------------. .-------.    |
#  | ospfd | |      |     p0     |    net_tap    |    x-p0    | | zebra |    |
#  '-------' |      |            +---------------+            | '-------'    |
#      .----------. | 172.16.0.1 |               | 172.16.0.2 |.----------.  |
#      | gr-loop0 | '------------'               '------------'|    lo    |  |
#      '----------'       |                             |      |          |  |
#           |      ping <------------------------------------> | 16.0.0.1 |  |
#           |             |                             |      '----------'  |
#           '-------------'                             '--------------------'

. $(dirname $0)/_init_frr.sh

create_interface p0
set_ip_address p0 172.16.0.1/24

start_frr_on_namespace ospf-peer
ip link set x-p0 netns ospf-peer

ip -n grout l set p0 up
ip -n ospf-peer l set x-p0 up

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal
ip router-id 172.16.0.1
!
debug ospf event
debug ospf packet all
!
interface lo
	ip address 17.0.0.1/24
exit
!
interface p0
	ip ospf hello-interval 1
exit
!
!
router ospf
	ospf router-id 172.16.0.1
	network 172.16.0.0/24 area 10.0.0.1
	network 17.0.0.0/24 area 10.0.0.1
exit
!
EOF

vtysh -N ospf-peer <<-EOF
configure terminal
ip router-id 172.16.0.2
!
debug ospf event
debug ospf packet all
!
interface lo
	ip address 16.0.0.1/24
exit
!
interface x-p0
	ip address 172.16.0.2/24
	ip ospf hello-interval 1
exit
!
router ospf
	ospf router-id 172.16.0.2
	network 172.16.0.0/24 area 10.0.0.1
	network 16.0.0.0/24 area 10.0.0.1
exit
end
!
EOF

attempts=60
while ! vtysh -c 'show ip ospf neighbor json' | jq '.neighbors."172.16.0.2"[0].converged == "Full"' -e ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

attempts=30
while ! vtysh -c 'show ip route ospf json' | jq '."16.0.0.1/32"[0].protocol == "ospf"' -e ; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF failed to get routes."
	fi
	attempts=$((attempts - 1))
done

grcli ping 16.0.0.1 count 1
