#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christopher Dziomba, Deutsche Telekom AG

# This test verifies that a remote EVPN VTEP reachable in both address
# families is programmed as two distinct grout nexthops.
#
# A VTEP is always IPv4, so zebra keeps two nexthop entries for it: the IPv4
# AFI uses the native address (172.16.0.1) while the IPv6 AFI uses its
# v4-mapped form (::ffff:172.16.0.1). Both must be installed as separate
# grout nexthops with their own ids.
#
# Initial convergence alone does not catch a collapse of the two entries: each
# route is installed right after the nexthop it references, so it holds a valid
# pointer whatever the id ends up being. The failure only shows up on a later
# route that resolves through an already installed nexthop, because zebra then
# sends the route alone, referencing an id that grout no longer knows about.
#
# Success criteria:
#   - Host-A and Host-B can ping each other in both address families.
#   - A prefix advertised afterwards through the same VTEP is installed in
#     grout's FIB and is reachable.

. $(dirname $0)/_init_frr.sh

# right side (grout) -----------------------------------------------------------
create_interface p0
set_ip_address p0 172.16.0.2/24

# left side (Linux peer) -------------------------------------------------------
start_frr evpn-peer

ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv6.conf.all.forwarding=1

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
grcli interface add vxlan vxlan-l3 vni 1000 local 172.16.0.2 vrf tenant

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

wait_event "nh new: type=L3 id=[0-9]+ iface=vxlan-l3 vrf=tenant origin=zebra family=ipv4 addr=172.16.0.1 state=reachable mac=$rmac"

vtysh -c "show bgp l2vpn evpn route type 5"
grcli route show vrf tenant
grcli nexthop show vrf tenant

# -- Verify L3 connectivity through VXLAN overlay (IPv4) -----------------------
ip netns exec host-b ping -i0.1 -c3 -W1 16.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 48.0.0.2

# -- Verify L3 connectivity through VXLAN overlay (IPv6) -----------------------
ip netns exec host-b ping -6 -i0.1 -c3 -W1 fd00:16::2
ip netns exec host-a ping -6 -i0.1 -c3 -W1 fd00:48::2

# -- Advertise a new IPv4 prefix through the same VTEP --------------------------
# Both nexthop entries are installed by now. zebra considers the IPv4 one
# already programmed, so a new IPv4 prefix resolving through it is pushed as a
# route referencing that id, without re-sending the nexthop itself. If the two
# entries were collapsed into a single grout nexthop, that id no longer exists
# and the route is rejected with ENOENT.
mark_events

ip -n evpn-peer addr add 17.0.0.1/24 dev p1

wait_event -t 30 'route4 add: vrf=tenant 17.0.0.0/24'

grcli route show vrf tenant
grcli nexthop show vrf tenant

grcli route show vrf tenant | grep -qF "17.0.0.0/24" \
	|| fail "IPv4 prefix 17.0.0.0/24 missing from grout FIB"

ip netns exec host-b ping -i0.1 -c3 -W1 17.0.0.1
