#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# This test verifies EVPN/VXLAN type-2 (MAC/IP) and type-3 (flood VTEP) IPv6
# route exchange between FRR+Grout and a standalone FRR+Linux peer. Each side
# has a bridge with a VXLAN member (VNI 100) configured with an IPv6 local VTEP
# (encapsulation address) and a host connected to a local port. BGP EVPN
# advertises locally learned MACs and flood VTEPs to the remote peer.
#
# Success criteria:
#   - Both sides exchange EVPN type-3 routes (flood VTEPs installed).
#   - Host-A and Host-B can ping each other through the VXLAN overlay.
#   - Both sides learn the remote MAC via EVPN type-2 routes.
#
#     .-------------------------.          .-------------------------.
#     |       evpn-peer         |          |         grout           |
#     |                         |          |                         |
#     | +----------+            |          |            +----------+ |
#     | | vxlan100 |            |          |            | vxlan100 | |
#     | +----+-----+            |          |            +-----+----+ |
#     |      |                  |          |                  |      |
#     |  +---+---+              |          |              +---+---+  |
#     |  | br100 |              |          |              | br100 |  |
#     |  +---+---+              |          |              +---+---+  |
#     |      |           .1     |          |    .2            |      |
#     |  +---+---+    +-------+ |          | +------+     +---+---+  |
#     |  |   p1  |    | x-p0  | |          | |  p0  |     |   p1  |  |
#     |  +---+---+    +---+---+ |          | +---+--+     +---+---+  |
#     '------|------------|-----'          '-----|------------|------'
#            |            |                      |            |
#     .------|--------.   |  <----- BGP ----->   |    .-------|------.
#     |      |        |   |                      |    |       |      |
#     |  +---+----+   |   `----------------------'    |   +---+----+ |
#     |  |  x-p1  |   |           underlay            |   |  x-p1  | |
#     |  +--------+   |          3fff::/64            |   +--------+ |
#     |      .2       |                               |       .3     |
#     |               | <= = = = = = = = = = = = = => |              |
#     |    host-a     |           overlay             |    host-b    |
#     '---------------'          fc00::/64            '--------------'

set -e
zebra=$(PATH="$1/frr_install/sbin:$1/frr_install/bin:$PATH" command -v zebra)
frr_version=$($zebra --version | sed -En 's/zebra version //p')
min_version=$(printf '%s\n%s\n' "$frr_version" "10.6.0" | sort -V | head -n1)
if ! [ "$min_version" = "10.6.0" ]; then
	echo "$0: FRR $frr_version does not support IPv6 underlay addresses"
	exit 125
fi

. $(dirname $0)/_init_frr.sh

# right side -------------------------------------------------------------------
create_interface p0
set_ip_address p0 3fff::2/64

# left side --------------------------------------------------------------------
start_frr evpn-peer 0

ip netns exec evpn-peer sysctl -qw net.ipv6.conf.all.forwarding=1

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 3fff::1/64 dev x-p0

ip -n evpn-peer link add br100 type bridge
ip -n evpn-peer link set br100 up

ip -n evpn-peer link add vxlan100 type vxlan id 100 local 3fff::1 dstport 4789 nolearning
ip -n evpn-peer link set vxlan100 master br100
ip -n evpn-peer link set vxlan100 up

# Host-A: veth pair, one end in host-a, other end in evpn-peer bridge
ip -n evpn-peer link add p1 type veth peer name x-p1
ip -n evpn-peer link set p1 master br100
ip -n evpn-peer link set p1 up

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add fc00::2/64 dev x-p1

# BGP EVPN on peer
vtysh -N evpn-peer <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.1
 no bgp default ipv4-unicast
 no bgp default ipv6-unicast

 neighbor 3fff::2 remote-as 65000

 address-family l2vpn evpn
  neighbor 3fff::2 activate
  advertise-all-vni
 exit-address-family
exit
EOF

mark_events

# BGP EVPN on Grout
vtysh <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.2
 no bgp default ipv4-unicast
 no bgp default ipv6-unicast

 neighbor 3fff::1 remote-as 65000

 address-family l2vpn evpn
  neighbor 3fff::1 activate
  advertise-all-vni
 exit-address-family
exit
EOF

# Workaround for https://github.com/FRRouting/frr/issues/21190
#
# Zebra silently ignores VNI and FDB notifications until advertise-all-vni has
# taken effect and it knows about the VNI. Create the VXLAN interface before any
# bridge port that could trigger MAC learning, and wait for zebra to learn about
# VNI 100 before proceeding.
attempts=0
while ! vtysh -c "show evpn" | grep -q "L2 VNIs"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show evpn"
		fail "EVPN not enabled in zebra"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

grcli interface add bridge br100
grcli interface add vxlan vxlan100 vni 100 local 3fff::2 domain br100

attempts=0
while ! vtysh -c "show evpn vni 100" | grep -q "VNI: 100"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show evpn vni 100"
		fail "zebra did not learn VNI 100"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

create_interface p1 domain br100

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add fc00::3/64 dev x-p1

# -- Wait for EVPN type-3 (flood VTEP) exchange -------------------------------
attempts=0
while ! bridge -n evpn-peer fdb show dev vxlan100 | grep -qF 3fff::2; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -N evpn-peer -c "show evpn vni 100"
		fail "Linux peer did not learn remote VTEP 3fff::2"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

wait_event "flood add: vtep vrf=main 3fff::1 vni=100"

bridge -n evpn-peer fdb show dev vxlan100
grcli fdb show
grcli flood vtep show

# -- Verify L2 connectivity through VXLAN overlay -----------------------------

# Ping triggers ARP which triggers MAC learning + EVPN type-2 advertisement.
ip netns exec host-a ping -i0.1 -c3 -W1 fc00::3
ip netns exec host-b ping -i0.1 -c3 -W1 fc00::2

grcli fdb show iface vxlan100
bridge -n evpn-peer fdb show dev vxlan100

# -- Verify EVPN type-2 (MAC/IP) learned on both sides
mac_a=$(ip netns exec host-a cat /sys/class/net/x-p1/address)

wait_event "fdb add: bridge=br100 $mac_a.* vtep=3fff::1.* extern"

attempts=0
while ! vtysh -c "show bgp l2vpn evpn route type 2" | grep -qF "$mac_a"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show bgp l2vpn evpn route type 2"
		fail "FRR did not learn type 2 route"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

mac_b=$(ip netns exec host-b cat /sys/class/net/x-p1/address)
attempts=0
while ! vtysh -N evpn-peer -c "show bgp l2vpn evpn route type 2" | grep -qF "$mac_b"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -N evpn-peer -c "show bgp l2vpn evpn route type 2"
		fail "EVPN peer did not learn type 2 route"
	fi
	sleep 1
	attempts=$((attempts + 1))
done
attempts=0
while ! bridge -n evpn-peer fdb show dev vxlan100 | grep -q "$mac_b.*extern"; do
	if [ "$attempts" -ge 10 ]; then
		bridge -n evpn-peer fdb show dev vxlan100
		fail "EVPN peer did not program FDB entry in bridge"
	fi
	sleep 1
	attempts=$((attempts + 1))
done
