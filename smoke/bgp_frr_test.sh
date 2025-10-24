#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Andrea Panattoni

# This test leverages the following architecture to test the BGP route exchange between an
# FRR+Grout setup and a pure FRR BGP peer. At the end of the configuration phase, Host-A
# and Host-B must be able to ping each other, as the respective default gateway routers
# have learned the correct routes.
#
#
# ┌────────────────────────────────┐      ┌──────────────────────────────────┐
# │                                │      │                                  │
# │                                │      │     << System under test >>      │
# │                                │      │                                  │
# │         frr-bgp-peer           │      │           FRR + Grout            │
# │                                │      │                                  │
# │ ┌───────────┐   ┌────────────┐ │      │ ┌────────────┐    ┌────────────┐ │
# │ │ to-host-a │   │     p0     │ │      │ │     p0     │    │     p1     │ │
# └─┤           ├───┤            ├─┘      └─┤            ├────┤            ├─┘
#   │ 16.0.0.1  │   │ 172.16.0.1 │          │ 172.16.0.1 │    │ 16.1.0.1   │
#   └────┬──────┘   └─────────┬──┘          └──┬─────────┘    └────┬───────┘
#        │                    │                │                   │
#        │<<veth>>            │                │            <<tap>>│
#        │                    │     <<tap>>    │                   │
#   ┌────┴─────┐              └────────────────┘              ┌────┴─────┐
#   │   eth0   │                                              │   eth0   │
# ┌─│          ├─┐                                          ┌─│          ├─┐
# │ │ 16.0.0.2 │ │                                          │ │ 16.1.0.2 │ │
# │ └──────────┘ │        <-----      PING     ----->       │ └──────────┘ │
# │    Host-A    │                                          │    Host-B    │
# └──────────────┘                                          └──────────────┘
#


. $(dirname $0)/_init_frr.sh

create_interface p0 mac f0:0d:ac:dc:00:00
create_interface p1 mac f0:0d:ac:dc:00:01

netns_add ns-a
netns_add ns-b

# Configure Host-B
ip link set p1 netns ns-b
ip -n ns-b link set p1 address ba:d0:ca:ca:00:01
ip -n ns-b link set p1 up
ip -n ns-b addr add 16.1.0.2/24 dev p1
ip -n ns-b route add default via 16.1.0.1
ip -n ns-b addr show

set_ip_address p1 16.1.0.1/24
set_ip_address p0 172.16.0.1/24

# Create and start an FRR instance for the BGP peer
frr_bgp_peer_namespace="frr-bgp-peer"
start_frr_on_namespace $frr_bgp_peer_namespace
ip link set p0 netns $frr_bgp_peer_namespace

ip -n ns-a link add eth0 type veth peer name to-host-a
ip -n ns-a link set to-host-a up
ip -n ns-a link set eth0 up

# Configure Host-A
ip -n ns-a link set eth0 address ba:d0:ca:ca:00:02
ip -n ns-a link set eth0 up
ip -n ns-a addr add 16.0.0.2/24 dev eth0
ip -n ns-a route
ip -n ns-a addr show
ip -n ns-a route add default via 16.0.0.1


# Configure FRR BGP peer router
ip -n ns-a link set to-host-a netns $frr_bgp_peer_namespace

vtysh -N $frr_bgp_peer_namespace <<-EOF
	configure terminal

	log file $tmp/frr-bgp-peer.logs

	interface p0
		ip address 172.16.0.2/24
	exit

	interface to-host-a
		ip address 16.0.0.1/24
	exit

	router bgp 43
	no bgp ebgp-requires-policy
	no bgp network import-check

	neighbor 172.16.0.1 remote-as 44

	address-family ipv4 unicast
	network 16.0.0.0/24
	exit-address-family
	exit
EOF


# Configure Grout loopback to work with BGP
ip addr add 172.16.0.1/32 dev gr-loop0
ip addr add 16.1.0.1/32 dev gr-loop0
ip route add 172.16.0.0/24 dev gr-loop0 via 172.16.0.1
ip route add 16.1.0.0/24 dev gr-loop0 via 16.1.0.1

# Configure Grout FRR instance
vtysh <<-EOF
	configure terminal

	log file $tmp/frr.logs

	debug zebra events
	debug zebra kernel
	debug zebra rib
	debug zebra nht detailed
	debug zebra pseudowires
	debug zebra pbr
	debug zebra vxlan
	debug zebra nexthop
	debug bgp keepalives
	debug bgp neighbor-events
	debug bgp nht
	debug bgp updates detail
	debug bgp updates in
	debug bgp updates out
	debug bgp zebra
	debug vrf

	router bgp 44
	bgp router-id 172.16.0.1
	no bgp ebgp-requires-policy
	no bgp network import-check

	neighbor 172.16.0.2 remote-as 43
	neighbor 172.16.0.2 update-source 172.16.0.1
	neighbor 172.16.0.2 interface gr-loop0
	neighbor 172.16.0.2 ip-transparent

	address-family ipv4 unicast
	network 16.1.0.0/24
	exit-address-family
	exit
EOF

dump_test_info() {
	# Debug BGP peer router
	cat $tmp/frr-bgp-peer.logs
	vtysh -N $frr_bgp_peer_namespace -c "show running-config"
	vtysh -N $frr_bgp_peer_namespace -c "show interface"
	vtysh -N $frr_bgp_peer_namespace -c "show ip route"
	vtysh -N $frr_bgp_peer_namespace -c "show bgp summary"
	vtysh -N $frr_bgp_peer_namespace -c "show bgp ipv4"
	ip netns exec $frr_bgp_peer_namespace ip addr
	ip netns exec $frr_bgp_peer_namespace ip route

	# Debug grout+FRR router
	cat $tmp/frr.logs
	vtysh -c "show running-config"
	vtysh -c "show interface"
	vtysh -c "show ip route"
	vtysh -c "show bgp summary"
	vtysh -c "show bgp ipv4"

	grcli route show
	grcli interface show
	grcli nexthop show
}

trap dump_test_info ERR

# Wait for BGP routes to be exchanged
SECONDS=0
expected_route_line="16.0.0.0/24[[:space:]]+type=L3.*origin=zebra"
while ! grcli route show | grep -qE "${expected_route_line}"; do
	if [ "$SECONDS" -ge "10" ]; then
		fail "BGP route not learned in Grout"
	fi
	sleep 0.5
done

expected_frr_bgp_peer_route_line="B>\* 16.1.0.0/24"
while ! vtysh -N $frr_bgp_peer_namespace -c "show ip route" | grep -q "${expected_frr_bgp_peer_route_line}"; do
	if [ "$SECONDS" -ge "10" ]; then
		fail "BGP route not learned in FRR BGP Peer"
	fi
	sleep 0.5
done

# Verify host-a can ping host-b
ip netns exec ns-a ping -i0.01 -c3 -n 16.1.0.2
ip netns exec ns-b ping -i0.01 -c3 -n 16.0.0.2
