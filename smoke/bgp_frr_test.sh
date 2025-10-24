#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Andrea Panattoni

. $(dirname $0)/_init_frr.sh

p0=${run_id}0
p1=${run_id}1

create_interface $p0 f0:0d:ac:dc:00:00
create_interface $p1 f0:0d:ac:dc:00:01

netns_add ns-a
netns_add ns-b

ip link set $p1 netns ns-b
ip -n ns-b link set $p1 address ba:d0:ca:ca:00:01
ip -n ns-b link set $p1 up
ip -n ns-b addr add 16.1.0.2/24 dev $p1
ip -n ns-b route add default via 16.1.0.1
ip -n ns-b addr show

set_ip_address $p1 16.1.0.1/24
set_ip_address $p0 172.16.0.1/24

podman build --tag frr-bgp-peer-image $(dirname $0)/images/frrbgp

podman run --name frr-bgp-peer --detach --rm --network none --cap-add=cap_net_admin,cap_net_raw,cap_sys_admin frr-bgp-peer-image
until [ "`podman inspect -f {{.State.Running}} frr-bgp-peer`"=="true" ]; do
    sleep 0.1;
done;

cat >> $tmp/cleanup <<EOF
podman kill frr-bgp-peer
EOF

SECONDS=0
while ! podman exec frr-bgp-peer pidof bgpd; do
	if [ "$SECONDS" -ge "5" ]; then
		echo "BGP daemon not working in FRR BGP peer"
		exit 1
	fi
	sleep 0.1
done

frr_bgp_pid="$(podman container inspect frr-bgp-peer --format '{{ .State.Pid }}')"
ip link set $p0 netns "/proc/${frr_bgp_pid}/ns/net"

ip link add frr-to-host-a type veth peer name host-a-to-frr
ip link set frr-to-host-a up
ip link set host-a-to-frr up

cat >> $tmp/cleanup <<EOF
ip link delete host-a-to-frr
ip link delete frr-to-host-a
EOF




ip link set host-a-to-frr netns ns-a
ip -n ns-a link set host-a-to-frr address ba:d0:ca:ca:00:02
ip -n ns-a link set host-a-to-frr up
ip -n ns-a addr add 16.0.0.2/24 dev host-a-to-frr
ip -n ns-a route
ip -n ns-a addr show
ip -n ns-a route add default via 16.0.0.1



ip link set frr-to-host-a netns "/proc/${frr_bgp_pid}/ns/net"

podman exec -i frr-bgp-peer vtysh <<-EOF
	configure terminal
	interface $p0
		ip address 172.16.0.2/24
	exit

	interface frr-to-host-a
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

vtysh <<-EOF
	configure terminal

	log file $tmp/frr.logs
	
	debug zebra events
	debug zebra kernel
	debug zebra rib
	debug zebra nht
	debug zebra vxlan
	debug zebra nexthop
	debug bgp keepalives
	debug bgp neighbor-events
	debug bgp nht
	debug bgp updates in
	debug bgp updates out
	debug bgp zebra

	router bgp 44
	bgp router-id 192.168.1.1
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

sleep 1

ip addr add 172.16.0.1/32 dev gr-loop0
ip addr add 16.1.0.1/32 dev gr-loop0
ip route add 172.16.0.0/24 dev gr-loop0 via 172.16.0.1
ip route add 16.1.0.0/24 dev gr-loop0 via 16.1.0.1
ip route


sleep 5

podman exec frr-bgp-peer vtysh -c "show running-config"
podman exec frr-bgp-peer cat /etc/frr/frr.log
podman logs frr-bgp-peer
podman exec frr-bgp-peer vtysh -c "show interface"
podman exec frr-bgp-peer vtysh -c "show ip route"
podman exec frr-bgp-peer vtysh -c "show bgp summary"
podman exec frr-bgp-peer vtysh -c "show bgp ipv4"
podman exec frr-bgp-peer ip addr
podman exec frr-bgp-peer ip route

cat $tmp/frr.logs
vtysh -c "show running-config"
vtysh -c "show interface"
vtysh -c "show ip route"
vtysh -c "show bgp summary"
vtysh -c "show bgp ipv4"

ip netns exec ns-a ip route



ip netns exec ns-a ping -i0.01 -c3 -n 16.1.0.2
ip netns exec ns-b ping -i0.01 -c3 -n 16.0.0.2
