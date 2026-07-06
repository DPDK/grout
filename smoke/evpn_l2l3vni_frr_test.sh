#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# This test verifies that L2 VNI and L3 VNI coexist correctly in the same VRF.
# When both an L3 VNI (1000) and an L2 VNI (100) are present, EVPN type-5
# (IP prefix) L3VPN routing must use the L3 VNI VXLAN interface and L2
# bridging must use the L2 VNI.
#
# Success criteria:
#   - Type-5 routes are exchanged and installed via the L3 VNI.
#   - Host-A and Host-B can ping each other through the L3 VXLAN overlay.
#   - Type-2/type-3 routes are exchanged via the L2 VNI.
#   - Host-C and Host-D can ping each other through the L2 VXLAN overlay.
#   - Host-A and Host-B can talk to both Host-C and Host-D crossing the L3
#     VXLAN boundary.
#
#                                BGP/VXLAN underlay
#                    +---------+    172.16.0.0/24    +---------+
#                    |  x-p0   |-+-+-+-+-+-+-+-+-+-+-|  p0     |
#   .----------------|         |--------.    .-------|         |--------------.
#   | evpn-peer      +---------+        |    |       +---------+       grout  |
#   |    ............... .1 ....        |    |    ...... .2 ..............    |
#   |    .                     .        |    |    .                      .    |
#   | .- . - - - - - - - - - - . - - .  |    | .- . - - - - - - - - - - -.-.  |
#   | '  .        vrf tenant   .     '  |    | '  .  vrf tenant          .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  .                     .     '  |    | '  .                      .  ' |
#   | '  . +-------+           .     '  |    | '  .            +-------+ .  ' |
#   | '  . | br-l3 |      +--------+ '  |    | ' +--------+    | br-l3 | .  ' |
#   | '  . +---+---+      | vni100 | '  |    | ' | vni100 |    +---+---+ .  ' |
#   | '  .     |          +----+---+ '  |    | ' +--+-----+        |     .  ' |
#   | ' +------+--+            |     '  |    | '    |            +-+-------+' |
#   | ' | vni-l3  |        +---+---+ '  |    | ' +--+----+       |  vni-l3 |' |
#   | ' +---------+     .1 | br100 | '  |    | ' | br100 | .4    +---------+' |
#   | '                    +---+---+ '  |    | ' +--+----+                  ' |
#   | '    .1                  |     '  |    | '    |                  .1   ' |
#   | ' +------+            +--+---+ '  |    | ' +--+---+           +------+' |
#   | ' |  p1  |            |  p2  | '  |    | ' |  p2  |           |  p1  |' |
#   | ' +--+---+            +--+---+ '  |    | ' +--+---+           +--+---+' |
#   | '    |                   |     '  |    | '    |                  |    ' |
#   | '- - | - - - - - - - - - |- - -'  |    | '- - | - - - - - - - - -|- - ' |
#   '------|-------------------|--------'    '------|------------------|------'
#          |                   |                    |                  |
#     16.0.0.0/24          10.0.0.0/24       10.0.0.0/24          48.0.0.0/24
#          |                   |                    |                  |
#   .------+---.          .----+-----.       .------+---.          .---+------.
#   | +------+ |          | +------+ |       | +------+ |          | +------+ |
#   | | x-p1 | |          | | x-p2 | |       | | x-p2 | |          | | x-p1 | |
#   | +------+ |          | +------+ |       | +------+ |          | +------+ |
#   |   .2     |          |   .2     |       |   .3     |          |   .2     |
#   | host-a   |          |  host-c  |       |  host-d  |          |  host-b  |
#   '----------'          '----------'       '----------'          '----------'
#        ^                      ^                  ^                     ^
#        |                      '--- L2 VNI 100 ---'                     |
#        |                                                               |
#        '------------------------ L3 VPN VNI 1000 ----------------------'

. $(dirname $0)/_init_frr.sh

# right side (grout) -----------------------------------------------------------
create_interface p0
set_ip_address p0 172.16.0.2/24

# left side (Linux peer) -------------------------------------------------------
start_frr evpn-peer

ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.default.rp_filter=0

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 172.16.0.1/24 dev x-p0

# L3VNI VXLAN on the Linux peer (bridge+SVI required by Linux)
ip -n evpn-peer link add br-l3 type bridge
ip -n evpn-peer link set br-l3 up

ip -n evpn-peer link add vni-l3 type vxlan id 1000 local 172.16.0.1 dstport 4789 nolearning
ip -n evpn-peer link set vni-l3 master br-l3
ip -n evpn-peer link set vni-l3 up

# L2VNI VXLAN on the Linux peer
ip -n evpn-peer link add br100 type bridge
ip -n evpn-peer link set br100 up

ip -n evpn-peer link add vni100 type vxlan id 100 local 172.16.0.1 dstport 4789 nolearning
ip -n evpn-peer link set vni100 master br100
ip -n evpn-peer link set vni100 up

# VRF "tenant" on the peer, bind both bridges
ip -n evpn-peer link add tenant type vrf table 10
ip -n evpn-peer link set tenant up
ip -n evpn-peer link set br-l3 master tenant
ip -n evpn-peer link set br100 master tenant

# Routed port in the peer VRF (L3)
ip -n evpn-peer link add p1 type veth peer name x-p1
ip -n evpn-peer link set p1 master tenant
ip -n evpn-peer link set p1 up
ip -n evpn-peer addr add 16.0.0.1/24 dev p1
ip -n evpn-peer addr add 10.0.0.1/24 dev br100

# Bridged port on the peer (L2)
ip -n evpn-peer link add p2 type veth peer name x-p2
ip -n evpn-peer link set p2 master br100
ip -n evpn-peer link set p2 up

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add 16.0.0.2/24 dev x-p1
ip -n host-a route add default via 16.0.0.1

netns_add host-c
ip -n evpn-peer link set x-p2 netns host-c
ip -n host-c link set x-p2 up
ip -n host-c addr add 10.0.0.2/24 dev x-p2
ip -n host-c route add default via 10.0.0.1

# FRR config on the Linux peer
vtysh -N evpn-peer <<-EOF
configure terminal

vrf tenant
 vni 1000
exit-vrf

router bgp 65000
 bgp router-id 172.16.0.1
 no bgp default ipv4-unicast

 neighbor 172.16.0.2 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.2 activate
  advertise-all-vni
 exit-address-family
exit

router bgp 65000 vrf tenant
 bgp router-id 172.16.0.1

 address-family ipv4 unicast
  redistribute connected
 exit-address-family

 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
exit
EOF

# right side (grout) setup L3VPN + L2VNI ---------------------------------------
create_vrf tenant

# L3 VNI VXLAN in VRF mode (no bridge needed in grout)
grcli interface add vxlan vni-l3 vni 1000 local 172.16.0.2 vrf tenant

# L2 VNI: create directly in the bridge domain.
grcli interface add bridge br100 vrf tenant
grcli interface add vxlan vni100 vni 100 local 172.16.0.2 domain br100

create_interface p1 vrf tenant
set_ip_address p1 48.0.0.1/24
set_ip_address br100 10.0.0.4/24

create_interface p2 domain br100

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 48.0.0.2/24 dev x-p1
ip -n host-b route add default via 48.0.0.1

netns_add host-d
move_to_netns x-p2 host-d
ip -n host-d addr add 10.0.0.3/24 dev x-p2
ip -n host-d route add default via 10.0.0.4

mark_events

# FRR config on grout
vtysh <<-EOF
configure terminal

vrf tenant
 vni 1000
exit-vrf

router bgp 65000
 bgp router-id 172.16.0.2
 no bgp default ipv4-unicast

 neighbor 172.16.0.1 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.1 activate
  advertise-all-vni
 exit-address-family
exit

router bgp 65000 vrf tenant
 bgp router-id 172.16.0.2

 address-family ipv4 unicast
  redistribute connected
 exit-address-family

 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
exit
EOF

# -- Check L3VNI is recognized by both sides -----------------------------------
attempts=0
while ! vtysh -c "show evpn vni 1000" | grep -qF "L3"; do
	if [ "$attempts" -ge 5 ]; then
		vtysh -c "show evpn vni"
		fail "Grout FRR does not recognize VNI 1000 as L3VNI"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

attempts=0
while ! vtysh -N evpn-peer -c "show evpn vni 1000" | grep -qF "L3"; do
	if [ "$attempts" -ge 5 ]; then
		vtysh -N evpn-peer -c "show evpn vni"
		fail "Linux peer does not recognize VNI 1000 as L3VNI"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

# -- Check L2VNI is recognized by both sides -----------------------------------
attempts=0
while ! vtysh -c "show evpn vni 100" | grep -qF "VNI: 100"; do
	if [ "$attempts" -ge 5 ]; then
		vtysh -c "show evpn vni"
		fail "Grout FRR does not recognize VNI 100 as L2VNI"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

# -- Wait for EVPN type-5 route exchange (IPv4) --------------------------------
wait_event -t 10 'route4 add: vrf=tenant 16.0.0.0/24'

attempts=0
while ! ip -n evpn-peer route show vrf tenant proto bgp | grep -qF "48.0.0.0/24"; do
	[ "$attempts" -ge 5 ] && fail "Route 48.0.0.0/24 not installed in peer VRF tenant"
	sleep 1
	attempts=$((attempts + 1))
done

# -- Check RMAC is set on route nexthops and uses L3 VNI ----------------------
rmac=$(ip netns exec evpn-peer cat /sys/class/net/vni-l3/address)
wait_event "nh new: type=L3 id=[0-9]+ iface=vni-l3 vrf=tenant origin=zebra family=ipv4 addr=172.16.0.1 mac=$rmac flags=static remote"

# -- Verify L3 connectivity through L3 VNI VXLAN overlay ----------------------
ip netns exec host-b ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 48.0.0.2

# -- Verify L2 connectivity through L2 VNI VXLAN overlay ----------------------
wait_event "flood add: vtep vrf=main 172.16.0.1 vni=100"

ip netns exec host-c ping -i0.1 -c3 -W1 10.0.0.3
ip netns exec host-d ping -i0.1 -c3 -W1 10.0.0.2

# -- Verify L3 connectivity across L2 and L3 VXLAN overlays ------------------
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.3

ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.2
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.3

ip netns exec host-c ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-c ping -i0.1 -c3 -W1 48.0.0.2

ip netns exec host-d ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-d ping -i0.1 -c3 -W1 48.0.0.2
