#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# This test verifies EVPN/VXLAN type-2 (MAC/IP) and type-3 (flood VTEP) route
# exchange between FRR+Grout and a standalone FRR+Linux peer. Each side has
# a bridge with a VXLAN member (VNI 100) and a host connected to a local port.
# BGP EVPN advertises locally learned MACs and flood VTEPs to the remote peer.
#
# Success criteria:
#   - Both sides exchange EVPN type-3 routes (flood VTEPs installed).
#   - Host-A and Host-B can ping each other through the VXLAN overlay.
#   - Both sides learn the remote MAC via EVPN type-2 routes.
#
#      - - - - - - - - - - - - -            - - - - - - - - - - - - -
#     |       evpn-peer         |          |         grout           |
#
#     | +----------+            |          |            +----------+ |
#       | vxlan100 |                                    | vxlan100 |
#     | +----+-----+            |          |            +-----+----+ |
#            |                                                |
#     |  +---+---+              |          |              +---+---+  |
#        | br100 |                                        | br100 |
#     |  +---+---+              |          |              +---+---+  |
#            |           .1                     .2            |
#     |  +---+---+    +-------+ |          | +------+     +---+---+  |
#        |   p1  |    | x-p0  |              |  p0  |     |   p1  |
#     |  +---+---+    +---+---+ |          | +---+--+     +---+---+  |
#      - - - |- - - - - - |- - -            - - -| - - - - - -| - - -
#            |            |                      |            |
#      - - - |- - - - .   |  <----- BGP ----->   |     - - - -| - - -
#     |      |        |   |                      |    |       |      |
#        +---+----+       `----------------------'        +---+----+
#     |  |  x-p1  |   |            underlay           |   |  x-p1  | |
#        +--------+              172.16.0.0/24            +--------+
#     |      .2       |                               |       .3     |
#                       <= = = = = = = = = = = = = =>
#     |    host-a     |           overlay             |    host-b    |
#      - - - - - - - -           10.0.0.0/24           - - - - - - - '

. $(dirname $0)/_init_frr.sh

# right side -------------------------------------------------------------------
create_interface p0
set_ip_address p0 172.16.0.2/24

grcli interface add bridge br100
create_interface p1 domain br100
grcli interface add vxlan vxlan100 vni 100 local 172.16.0.2 domain br100

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 10.0.0.3/24 dev x-p1

# left side --------------------------------------------------------------------
start_frr evpn-peer 0

ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.default.rp_filter=0

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 172.16.0.1/24 dev x-p0

ip -n evpn-peer link add br100 type bridge
ip -n evpn-peer link set br100 up

ip -n evpn-peer link add vxlan100 type vxlan id 100 local 172.16.0.1 dstport 4789 nolearning
ip -n evpn-peer link set vxlan100 master br100
ip -n evpn-peer link set vxlan100 up

# Host-A: veth pair, one end in host-a, other end in evpn-peer bridge
ip -n evpn-peer link add p1 type veth peer name x-p1
ip -n evpn-peer link set p1 master br100
ip -n evpn-peer link set p1 up

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add 10.0.0.2/24 dev x-p1

# BGP EVPN on peer
vtysh -N evpn-peer <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.1
 no bgp default ipv4-unicast

 neighbor 172.16.0.2 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.2 activate
  advertise-all-vni
 exit-address-family
exit
EOF

# BGP EVPN on Grout
vtysh <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.2
 no bgp default ipv4-unicast

 neighbor 172.16.0.1 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.1 activate
  advertise-all-vni
 exit-address-family
exit
EOF

# -- Wait for EVPN type-3 (flood VTEP) exchange -------------------------------
attempts=0
while ! bridge -n evpn-peer fdb show dev vxlan100 | grep -qF 172.16.0.2; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -N evpn-peer -c "show evpn vni 100"
		fail "Linux peer did not learn remote VTEP 172.16.0.2"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

attempts=0
while ! grcli flood vtep show | grep -qF 172.16.0.1; do
	if [ "$attempts" -ge 10 ]; then
		grcli flood vtep show
		fail "Grout did not learn remote VTEP 172.16.0.1"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

bridge -n evpn-peer fdb show dev vxlan100
grcli fdb show
grcli flood vtep show

# -- Verify L2 connectivity through VXLAN overlay -----------------------------

# Ping triggers ARP which triggers MAC learning + EVPN type-2 advertisement.
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.3
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.2

grcli fdb show iface vxlan100
bridge -n evpn-peer fdb show dev vxlan100

# -- Verify EVPN type-2 (MAC/IP) learned on both sides
mac_a=$(ip netns exec host-a cat /sys/class/net/x-p1/address)
attempts=0
while ! vtysh -c "show bgp l2vpn evpn route type 2" | grep -qF "$mac_a"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show bgp l2vpn evpn route type 2"
		fail "FRR did not learn type 2 route"
	fi
	sleep 1
	attempts=$((attempts + 1))
done
attempts=0
while ! grcli fdb show iface vxlan100 extern | grep -qF "$mac_a"; do
	if [ "$attempts" -ge 10 ]; then
		grcli fdb show iface vxlan100
		fail "FRR did not program FDB entry"
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
