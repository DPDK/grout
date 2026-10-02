#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

# Verify that IS-IS Segment Routing automatically installs LSPs in grout via
# dplane_grout. isisd computes the penultimate-hop LSP for the peer's node SID
# and sends it to zebra → dplane_grout → grout LFIB.
#
# Both grout and the peer use SRGB [16000, 23999]:
#   grout prefix SID  index 0 → label 16000  (explicit-null toward grout)
#   peer  prefix SID  index 1 → label 16001  (PHP at grout for peer)
#
# IS-IS SR installs at grout: in=16001, PHP (implicit-null), via 172.16.0.2
#
#                                                     .--------------------.
#                                                     |  netns "isis-peer" |
#  .--------..------------.                           |        .-------.   |
#  | zebra  ||   grout    |                           |        | isisd |   |
#  '--------'|            |                           |        '-------'   |
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

# Configure grout's FRR: IS-IS with Segment Routing
vtysh <<-EOF
configure terminal
!
ip router-id 172.16.0.1
!
interface lo
  ip address 17.0.0.1/32
exit
!
interface p0
  ip router isis smoke
  isis network point-to-point
exit
!
router isis smoke
  net 49.0000.0000.0001.00
  is-type level-2-only
  redistribute ipv4 connected level-2
  segment-routing on
  segment-routing global-block 16000 23999
  segment-routing node-msd 8
  segment-routing prefix 17.0.0.1/32 index 0 explicit-null
exit
!
EOF

start_frr isis-peer 0
ip link set x-p0 netns isis-peer

# Enable kernel MPLS in the peer netns so that FRR zebra can install the
# pop rule for its own node SID (label 16001) when IS-IS SR comes up.
ip netns exec isis-peer sysctl -wq net.mpls.platform_labels=1000
ip netns exec isis-peer sysctl -wq net.mpls.conf.x-p0.input=1

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
  is-type level-2-only
  redistribute ipv4 connected level-2
  segment-routing on
  segment-routing global-block 16000 23999
  segment-routing node-msd 8
  segment-routing prefix 16.0.0.1/32 index 1
exit
!
EOF

# Wait for IS-IS adjacency
attempts=60
while ! vtysh -c 'show isis neighbor json' | jq -e '.areas[0].circuits[0].state == "Up"'; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "IS-IS failed to connect to neighbor."
	fi
	attempts=$((attempts - 1))
done

# Wait for IS-IS route exchange
attempts=90
while ! vtysh -c 'show ip route isis json' | jq -e '."16.0.0.1/32"'; do
	sleep 1
	if [ "$attempts" -le 0 ]; then
		fail "IS-IS failed to get routes."
	fi
	attempts=$((attempts - 1))
done

# IS-IS SR installs LSP for peer's node SID (label 16001) in grout LFIB
wait_event -t 60 'mpls route add: vrf=main label=16001 .* origin=isis'

# IP connectivity via IS-IS learned route
grcli ping 16.0.0.1 count 3 delay 10
