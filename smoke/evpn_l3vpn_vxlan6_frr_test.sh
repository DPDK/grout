#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# This test verifies EVPN Type-5 (IP prefix) L3VPN connectivity using symmetric
# IRB (Integrated Routing and Bridging) over VXLAN between FRR+Grout and
# a standalone FRR+Linux peer.
#
# Each side has a VRF with an L3 VNI (1000) and a host connected to a local
# port. BGP EVPN advertises IPv4 and IPv6 prefixes (type-5 routes) and RMAC
# entries (type-2 routes with GR_NH_F_REMOTE nexthops) across the VXLAN overlay.
#
# Success criteria:
#   - Both sides exchange EVPN type-5 routes (IPv4 and IPv6 prefixes installed).
#   - Host-A and Host-B can ping each other through the L3 VXLAN overlay.
#   - IPv6 RMACs are installed as remote nexthops on the grout side.
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
#      16.0.0.0/24           '---------------------'       48.0.0.0/24
#      fd00:16::/64                 underlay               fd00:48::/64
#            |                      3fff::/64                     |
#    .-------|-----------.                             .----------|--------.
#    |   +---+----+      |                             |      +---+----+   |
#    |   |  x-p1  |      |                             |      |  x-p1  |   |
#    |   +--------+      | <= = = = = = = = = = = = => |      +--------+   |
#    |       .2          |        overlay L3VPN        |         .2        |
#    |                   |                             |  lo:10.0.0.1/24   |
#    |                   |                             |                   |
#    |    host-a         |                             |       host-b      |
#    '-------------------'                             '-------------------'

set -e
zebra=$(PATH="$1/frr_install/sbin:$1/frr_install/bin:$PATH" command -v zebra)
frr_version=$($zebra --version | sed -En 's/zebra version //p')
min_version=$(printf '%s\n%s\n' "$frr_version" "10.6.0" | sort -V | head -n1)
if ! [ "$min_version" = "10.6.0" ]; then
	echo "$0: FRR $frr_version does not support IPv6 underlay addresses"
	exit 125
fi

. $(dirname $0)/_init_frr.sh

# right side (grout) -----------------------------------------------------------
create_interface p0
set_ip_address p0 3fff::2/64

# left side (Linux peer) -------------------------------------------------------
start_frr evpn-peer

ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv6.conf.all.forwarding=1

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 3fff::1/64 dev x-p0

# Create L3VNI VXLAN on the Linux peer with a bridge+SVI (required by Linux)
ip -n evpn-peer link add br-l3 type bridge
ip -n evpn-peer link set br-l3 up

ip -n evpn-peer link add vxlan-l3 type vxlan id 1000 local 3fff::1 dstport 4789 nolearning
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
ip -n evpn-peer addr add fd00:16::1/64 dev p1

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add 16.0.0.2/24 dev x-p1
ip -n host-a route add default via 16.0.0.1
ip -n host-a addr add fd00:16::2/64 dev x-p1
ip -n host-a -6 route add default via fd00:16::1

# FRR config on the Linux peer
vtysh -N evpn-peer <<-EOF
configure terminal

vrf tenant
 vni 1000
exit-vrf

router bgp 65000
 bgp router-id 172.16.0.0
 no bgp default ipv4-unicast

 neighbor 3fff::2 remote-as 65000

 address-family l2vpn evpn
  neighbor 3fff::2 activate
  advertise-all-vni
 exit-address-family
exit

router bgp 65000 vrf tenant
 bgp router-id 172.16.0.0

 address-family ipv4 unicast
  redistribute connected
 exit-address-family

 address-family ipv6 unicast
  redistribute connected
 exit-address-family

 address-family l2vpn evpn
  advertise ipv4 unicast
  advertise ipv6 unicast
 exit-address-family
exit
EOF

# right side (grout) setup L3VPN -----------------------------------------------
create_vrf tenant

# L3 VNI VXLAN in VRF mode (no bridge needed in grout)
grcli interface add vxlan vxlan-l3 vni 1000 local 3fff::2 vrf tenant

create_interface p1 vrf tenant
set_ip_address p1 48.0.0.1/24
set_ip_address p1 fd00:48::1/64

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 48.0.0.2/24 dev x-p1
ip -n host-b addr add 10.0.0.1/24 dev lo
ip -n host-b route add default via 48.0.0.1
ip -n host-b addr add fd00:48::2/64 dev x-p1
ip -n host-b -6 route add default via fd00:48::1

mark_events

# FRR config on grout
vtysh <<-EOF
configure terminal

vrf tenant
 vni 1000
exit-vrf

router bgp 65000
 bgp router-id 172.16.0.1
 no bgp default ipv4-unicast

 neighbor 3fff::1 remote-as 65000

 address-family l2vpn evpn
  neighbor 3fff::1 activate
  advertise-all-vni
 exit-address-family
exit

router bgp 65000 vrf tenant
 bgp router-id 172.16.0.1

 address-family ipv4 unicast
  redistribute connected
 exit-address-family

 address-family ipv6 unicast
  redistribute connected
 exit-address-family

 address-family l2vpn evpn
  advertise ipv4 unicast
  advertise ipv6 unicast
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
wait_event -t 10 'route4 add: vrf=tenant 16.0.0.0/24'
wait_event 'route6 add: vrf=tenant fd00:16::/64'

# The peer should also have our routes by now, allow a few retries.
attempts=0
while ! ip -n evpn-peer route show vrf tenant proto bgp | grep -qF "48.0.0.0/24"; do
	[ "$attempts" -ge 5 ] && fail "Route 48.0.0.0/24 not installed in peer VRF tenant"
	sleep 1
	attempts=$((attempts + 1))
done
attempts=0
while ! ip -n evpn-peer -6 route show vrf tenant proto bgp | grep -qF "fd00:48::"; do
	[ "$attempts" -ge 5 ] && fail "Route fd00:48::/64 not installed in peer VRF tenant"
	sleep 1
	attempts=$((attempts + 1))
done

# -- Check RMAC is set on route nexthops ---------------------------------------
rmac=$(ip netns exec evpn-peer cat /sys/class/net/vxlan-l3/address)

wait_event "nh new: type=L3 id=[0-9]+ iface=vxlan-l3 vrf=tenant origin=zebra family=ipv6 addr=3fff::1 mac=$rmac flags=static remote"

vtysh -c "show bgp l2vpn evpn route type 5"
grcli route show vrf tenant
grcli nexthop show vrf tenant

# -- Verify L3 connectivity through VXLAN overlay (IPv4) -----------------------
ip netns exec host-b ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 48.0.0.2

# -- Verify L3 connectivity through VXLAN overlay (IPv6) -----------------------
ip netns exec host-b ping -6 -i0.1 -c3 -W1 fd00:16::2
ip netns exec host-a ping -6 -i0.1 -c3 -W1 fd00:48::2

# -- Verify local nexthop uses port, not VXLAN ---------------------------------
# Route to 10.0.0.0/24 (behind host-b) via local gateway 48.0.0.2. The nexthop
# for 48.0.0.2 must use port p1, not the VXLAN interface.
set_ip_route 10.0.0.0/24 48.0.0.2 tenant
grcli ping 10.0.0.1 vrf tenant count 3 delay 10
