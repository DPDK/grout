#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# Verify ARP suppression with FRR EVPN Type-2 MAC+IP routes.
#
# Both VTEPs have bridge SVIs. The Linux peer has neigh_suppress on the
# VXLAN interface and advertise-svi-ip in BGP. Grout has neigh_suppress on
# the bridge and neigh_snoop on the bridge to learn local neighbors.
#
# When hosts ARP for their gateways, the VTEPs learn the IP+MAC bindings
# and advertise them as Type-2 MAC+IP routes. Remote VTEPs install the
# neighbors and the suppress node answers ARP requests locally.
#
#     .-------------------------.          .-------------------------.
#     |       evpn-peer         |          |         grout           |
#     |                         |          |                         |
#     | +----------+            |          |            +----------+ |
#     | | vxlan100 | nh_suppr   |          |            | vxlan100 | |
#     | +----+-----+            |          |            +-----+----+ |
#     |      |                  |          |                  |      |
#     |  +---+---+              |          |              +---+---+  |
#     |  | br100 |              |          |     nh_suppr | br100 |  |
#     |  +---+---+              |          |              +---+---+  |
#     |      |           .1     |          |     .2           |      |
#     |  +---+---+    +-------+ |          | +------+     +---+---+  |
#     |  |   p1  |    | x-p0  | |          | |  p0  |     |   p1  |  |
#     |  +---+---+    +---+---+ |          | +---+--+     +---+---+  |
#     '------|------------|-----'          '-----|------------|------'
#            |            |                      |            |
#            |            |  <----- BGP ----->   |            |
#     .------|--------.   `----------------------'    .-------|------.
#     |  +---+----+   |           underlay            |   +---+----+ |
#     |  |  x-p1  |   |         172.16.0.0/24         |   |  x-p1  | |
#     |  +--------+   |                               |   +--------+ |
#     |      .2       |                               |       .3     |
#     |    host-a     |           overlay             |    host-b    |
#     '---------------'         10.0.0.0/24           '--------------'

. $(dirname $0)/_init_frr.sh

# right side -------------------------------------------------------------------
create_interface p0
set_ip_address p0 172.16.0.2/24

# left side --------------------------------------------------------------------
start_frr evpn-peer 0

ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec evpn-peer sysctl -qw net.ipv4.conf.default.rp_filter=0

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 172.16.0.1/24 dev x-p0

ip -n evpn-peer link add br100 type bridge
ip -n evpn-peer link set br100 up
# linux needs an IP address in order to learn neighbors
ip -n evpn-peer addr add 10.0.0.4/24 dev br100

ip -n evpn-peer link add vxlan100 type vxlan id 100 local 172.16.0.1 dstport 4789 nolearning
ip -n evpn-peer link set vxlan100 master br100
ip -n evpn-peer link set vxlan100 type bridge_slave neigh_suppress on learning off
ip -n evpn-peer link set vxlan100 up

ip -n evpn-peer link add p1 type veth peer name x-p1
ip -n evpn-peer link set p1 master br100
ip -n evpn-peer link set p1 up

netns_add host-a
ip -n evpn-peer link set x-p1 netns host-a
ip -n host-a link set x-p1 up
ip -n host-a addr add 10.0.0.2/24 dev x-p1
ip -n host-a route add default via 10.0.0.4

# BGP EVPN on peer with advertise-svi-ip for Type-2 MAC+IP routes.
vtysh -N evpn-peer <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.1
 no bgp default ipv4-unicast

 neighbor 172.16.0.2 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.2 activate
  advertise-all-vni
  advertise-svi-ip
 exit-address-family
exit
EOF

# BGP EVPN on grout.
vtysh <<-EOF
configure terminal

router bgp 65000
 bgp router-id 172.16.0.2
 no bgp default ipv4-unicast

 neighbor 172.16.0.1 remote-as 65000

 address-family l2vpn evpn
  neighbor 172.16.0.1 activate
  advertise-all-vni
  advertise-svi-ip
 exit-address-family
exit
EOF

# Wait for advertise-all-vni to take effect before creating bridge members.
attempts=0
while ! vtysh -c "show evpn" | grep -q "L2 VNIs"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show evpn"
		fail "EVPN not enabled in zebra"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

grcli interface add bridge br100 neigh_suppress on neigh_snoop on
grcli address add 10.0.0.1/24 iface br100
grcli interface add vxlan vxlan100 vni 100 local 172.16.0.2 domain br100

attempts=0
while ! vtysh -c "show evpn vni 100" | grep -q "VNI: 100"; do
	if [ "$attempts" -ge 10 ]; then
		vtysh -c "show evpn vni 100"
		fail "zebra did not learn VNI 100"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

mark_events
create_interface p1 domain br100

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 10.0.0.3/24 dev x-p1
ip -n host-b route add default via 10.0.0.1

# -- Wait for EVPN type-3 (flood VTEP) exchange -------------------------------
wait_event -t 10 "flood add:.*172.16.0.1.*vni=100"

# -- Trigger ARP learning on both sides ---------------------------------------
# Each host pings its gateway SVI. This makes the host ARP for the gateway,
# teaching the local VTEP the host's IP+MAC. FRR advertises the binding as
# a Type-2 MAC+IP route.
mark_events
ip netns exec host-a ping -c1 -W1 10.0.0.4
ip netns exec host-b ping -c1 -W1 10.0.0.1

# Also establish overlay connectivity.
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.3

# -- Wait for remote nexthop to be installed via DPLANE_OP_NEIGH_IP_INSTALL ---
wait_event -t 10 "nh new:.*addr=10.0.0.2.*flags=.*remote"

arp_suppress_fail() {
	local msg="$*"

	grcli nexthop show
	vtysh -c "show evpn arp-cache vni 100"
	ip -n evpn-peer neigh show dev br100
	ip -n evpn-peer neigh show dev vxlan100
	vtysh -N evpn-peer -c "show evpn mac vni 100"
	vtysh -N evpn-peer -c "show evpn arp-cache vni 100"

	fail "$msg"
}

vtysh -c 'show evpn arp-cache vni 100 json' |
	jq -e '."10.0.0.2" | select(.state == "active" and .type == "remote")' ||
	arp_suppress_fail "Missing remote ARP entry"
vtysh -N evpn-peer -c 'show evpn arp-cache vni 100 json' |
	jq -e '."10.0.0.3" | select(.state == "active" and .type == "remote")' ||
	arp_suppress_fail "Missing remote ARP entry"

# -- Verify ARP suppression ---------------------------------------------------

check_arp_suppression() {
	local src_ns=$1
	local dst_ns=$2
	local ip=$3
	local hex_ip=0x$(printf '%02x' ${ip//./ })

	# Flush neigh cache to force a new ARP request.
	ip -n $src_ns neigh flush dev x-p1

	# Send ARP from $src_ns. The near-side bridge should suppress it and
	# reply from the EVPN installed neighbor.
	ip netns exec $src_ns arping -b -c2 -w3 -I x-p1 $ip | tee $tmp/arping.out &
	arping_pid=$!

	# Capture on $dst_ns filtering only for ARP targeting $ip
	ip netns exec $dst_ns timeout 3 \
		tcpdump -c1 -tlpnn -i x-p1 "arp and arp[24:4] = $hex_ip" 2>&1 &&
		arp_suppress_fail "ARP request for $ip was flooded to $dst_ns (should have been suppressed)"

	# Wait for arping to finish.
	wait $arping_pid || arp_suppress_fail "No reply to ARP request"

	# Verify $src_ns received reply with the correct MAC.
	local mac=$(ip netns exec $dst_ns cat /sys/class/net/x-p1/address)
	grep -qi "$mac" $tmp/arping.out ||
		arp_suppress_fail "ARP reply did not contain expected MAC $mac_a"
}

# check that grout suppresses ARP requests from EVPN type 2 mac/ip routes
# exported by evpn-peer
check_arp_suppression host-b host-a 10.0.0.2

# check that evpn-peer (Linux stack) suppresses ARP requests from EVPN type
# 2 mac/ip routes exported by grout.
check_arp_suppression host-a host-b 10.0.0.3

# -- Final connectivity check through overlay ----------------------------------
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.2
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.3
