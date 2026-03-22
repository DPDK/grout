#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# This test verifies EVPN Type-5 (IP prefix) L3VPN connectivity using symmetric
# IRB (Integrated Routing and Bridging) over VXLAN between FRR+Grout and
# a standalone FRR+Linux peer.
#
# Each side has a VRF with an L3 VNI (1000) and a host connected to a local
# port. BGP EVPN advertises IP prefixes (type-5 routes) and RMAC entries
# (type-2 routes with GR_NH_F_REMOTE nexthops) across the VXLAN overlay.
#
# Success criteria:
#   - Both sides exchange EVPN type-5 routes (IP prefixes installed).
#   - Host-A and Host-B can ping each other through the L3 VXLAN overlay.
#   - RMACs are installed as remote nexthops on the grout side.
#
#   .-------------------------------.         .-----------------------------.
#   |           evpn-peer           |         |            grout            |
#   |                               |         |                             |
#   | .- - - - - - - .              |         |            .- - - - - - - . |
#   | '  vrf tenant  '              |         |            '  vrf tenant  ' |
#   | '              '              |         |            '              ' |
#   | '  +-------+   '              |         |            '              ' |
#   | '  | br-l3 |   '              |         |            '              ' |
#   | '  +---+---+   '              |         |            '              ' |
#   | '      |       '              |         |            '              ' |
#   | ' +----+-----+ '              |         |            ' +----------+ ' |
#   | ' | vxlan-l3 |...........     |         |    ..........| vxlan-l3 | ' |
#   | ' +----------+ '        .     |         |    .       ' +----------+ ' |
#   | '              '        .     |         |    .       '              ' |
#   | '      .1      '        .     |         |    .       '     .1       ' |
#   | '   +------+   '       .1     |         |   .2       '  +-------+   ' |
#   | '   |  p1  |   '   +--------+ |         | +------+   '  |   p1  |   ' |
#   | '   +--+---+   '   |  x-p0  | |         | |  p0  |   '  +---+---+   ' |
#   | '- - - |- - - -'   +---+----+ |         | +--+---+   '- - - |- - - -' |
#   '--------|---------------|------'         '----|--------------|---------'
#            |               |                     |              |
#            |               | <------- BGP  ----> |              |
#        16.0.0.0/24         '---------------------'         48.0.0.0/24
#            |                      underlay                      |
#    .-------|-----------.         172.16.0.0/24       .----------|--------.
#    |   +---+----+      |                             |      +---+----+   |
#    |   |  x-p1  |      |                             |      |  x-p1  |   |
#    |   +--------+      | <= = = = = = = = = = = = => |      +--------+   |
#    |       .2          |        overlay L3VPN        |         .2        |
#    |                   |                             |                   |
#    |    host-a         |                             |       host-b      |
#    '-------------------'                             '-------------------'

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

# Create L3VNI VXLAN on the Linux peer with a bridge+SVI (required by Linux)
ip -n evpn-peer link add br-l3 type bridge
ip -n evpn-peer link set br-l3 up

ip -n evpn-peer link add vxlan-l3 type vxlan id 1000 local 172.16.0.1 dstport 4789 nolearning
ip -n evpn-peer link set vxlan-l3 master br-l3
ip -n evpn-peer link set vxlan-l3 up

# Create VRF "tenant" on the peer and bind the L3VNI bridge as SVI
ip -n evpn-peer link add tenant type vrf table 10
ip -n evpn-peer link set tenant up
ip -n evpn-peer link set br-l3 master tenant

# Host-facing port in the peer VRF
ip -n evpn-peer link add p1 type veth peer name x-p1
ip -n evpn-peer link set p1 master tenant
ip -n evpn-peer link set p1 up
ip -n evpn-peer addr add 16.0.0.1/24 dev p1

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add 16.0.0.2/24 dev x-p1
ip -n host-a route add default via 16.0.0.1

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

# right side (grout) setup L3VPN -----------------------------------------------
create_vrf tenant

# L3 VNI VXLAN in VRF mode (no bridge needed in grout)
grcli interface add vxlan vxlan-l3 vni 1000 local 172.16.0.2 vrf tenant

create_interface p1 vrf tenant
set_ip_address p1 48.0.0.1/24

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 48.0.0.2/24 dev x-p1
ip -n host-b route add default via 48.0.0.1

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

# -- Wait for EVPN type-5 route exchange ---------------------------------------
attempts=0
while ! vtysh -c "show bgp l2vpn evpn route type 5" | grep -qF "16.0.0.0"; do
	if [ "$attempts" -ge 5 ]; then
		vtysh -c "show bgp l2vpn evpn route type 5"
		fail "Grout FRR did not learn type-5 route for 16.0.0.0/24"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

attempts=0
while ! vtysh -N evpn-peer -c "show bgp l2vpn evpn route type 5" | grep -qF "48.0.0.0"; do
	if [ "$attempts" -ge 5 ]; then
		vtysh -c "show bgp vrf tenant ipv4 unicast"
		vtysh -c "show bgp l2vpn evpn route"
		vtysh -N evpn-peer -c "show bgp l2vpn evpn route type 5"
		fail "Linux peer did not learn type-5 route for 48.0.0.0/24"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

# -- Wait for routes to be installed in VRF ------------------------------------
attempts=0
while ! grcli -j route show vrf tenant | jq -e '.[] | select(.destination == "16.0.0.0/24")'; do
	if [ "$attempts" -ge 5 ]; then
		grcli route show vrf tenant
		fail "Route 16.0.0.0/24 not installed in grout VRF tenant"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

attempts=0
while ! ip -n evpn-peer route show vrf tenant | grep -qF "48.0.0.0/24"; do
	if [ "$attempts" -ge 5 ]; then
		ip -n evpn-peer route show vrf tenant
		fail "Route 48.0.0.0/24 not installed in peer VRF tenant"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

# -- Check RMAC is set on the route nexthop ------------------------------------
attempts=0
while ! grcli nexthop show | grep -q "172.16.0.1.*remote"; do
	if [ "$attempts" -ge 10 ]; then
		grcli nexthop show
		fail "Remote RMAC not set on route nexthop"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

vtysh -c "show bgp l2vpn evpn route type 5"
grcli route show vrf tenant
grcli nexthop show vrf tenant

# -- Verify L3 connectivity through VXLAN overlay ------------------------------
ip netns exec host-b ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 48.0.0.2
