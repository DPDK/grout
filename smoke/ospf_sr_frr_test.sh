#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

# Verify that OSPF Segment Routing automatically installs LSPs in grout via
# dplane_grout. ospfd computes the penultimate-hop LSP for the peer's node SID
# and sends it to zebra → dplane_grout → grout LFIB.
#
# Both grout and the peer use SRGB [16000, 23999]:
#   grout prefix SID  index 0 → label 16000 (or 15000 depending on ospfd timing)
#   peer  prefix SID  index 1 → label 16001 (or 15001 depending on ospfd timing)
#
# OSPF-SR installs at grout: in=peer's SID, PHP (implicit-null), via 172.16.0.2
#
#                                                     .--------------------.
#                                                     |  netns "ospf-peer" |
#  .--------..------------.                           |        .-------.   |
#  | zebra  ||   grout    |                           |        | ospfd |   |
#  '--------'|            |                           |        '-------'   |
#  .-------. |      .------------.             .------------. .-------.    |
#  | ospfd | |      |     p0     |   net_tap   |    x-p0    | | zebra |    |
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

start_frr ospf-peer 0
move_to_netns x-p0 ospf-peer

# Enable kernel MPLS in the peer netns so that FRR zebra can install the
# pop rule for its own node SID (label 16001) when OSPF-SR comes up.
ip netns exec ospf-peer sysctl -wq net.mpls.platform_labels=17000
ip netns exec ospf-peer sysctl -wq net.mpls.conf.x-p0.input=1

# Configure grout's FRR: OSPF with Segment Routing
vtysh <<-EOF
configure terminal
ip router-id 172.16.0.1
!
interface lo
  ip address 17.0.0.1/32
exit
!
interface p0
  ip ospf hello-interval 1
  ip ospf network point-to-point
exit
!
router ospf
  ospf router-id 172.16.0.1
  network 172.16.0.0/24 area 0
  network 17.0.0.1/32 area 0
  router-info area
  segment-routing global-block 16000 23999
  segment-routing on
  segment-routing node-msd 8
  segment-routing prefix 17.0.0.1/32 index 0
exit
!
EOF

vtysh -N ospf-peer <<-EOF
configure terminal
ip router-id 172.16.0.2
!
interface lo
  ip address 16.0.0.1/32
exit
!
interface x-p0
  ip address 172.16.0.2/24
  ip ospf hello-interval 1
  ip ospf network point-to-point
exit
!
router ospf
  ospf router-id 172.16.0.2
  network 172.16.0.0/24 area 0
  network 16.0.0.1/32 area 0
  router-info area
  segment-routing global-block 16000 23999
  segment-routing on
  segment-routing node-msd 8
  segment-routing prefix 16.0.0.1/32 index 1
exit
!
EOF

attempts=60
while ! vtysh -c 'show ip ospf neighbor json' | jq -e '.neighbors."172.16.0.2"[0].converged == "Full"'; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

# Wait for OSPF route exchange
attempts=30
while ! vtysh -c 'show ip route ospf json' | jq -e '."16.0.0.1/32"'; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "OSPF failed to get routes."
	fi
	attempts=$((attempts - 1))
done

# OSPF-SR installs LSP for peer's node SID in grout LFIB
wait_event -t 60 'mpls route add: vrf=main label=1[56][0-9][0-9][0-9] .* origin=ospf'

# IP route is installed by dplane_grout synchronously with the RIB update above
grcli ping 16.0.0.1 count 1
