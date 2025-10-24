#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

create_interface p0 vrf 1
create_interface p1 vrf 2

for n in 0 1; do
	p=p$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p addr add 16.$n.0.1/16 dev lo
	ip -n $p route add default via 172.16.$n.1
done

set_ip_address p0 172.16.0.1/24
set_ip_address p1 172.16.1.1/24
set_vrf_iface 1
set_vrf_iface 2

# from 16.0.0.1 to 16.1.0.1, only one route lookup is done
set_ip_route 16.1.0.0/16 172.16.1.2 1 2
set_ip_route 16.1.0.0/16 172.16.1.2 2 2 # required for ARP resolution

# from 16.1.0.1 to 16.0.0.1, two route lookup are done
set_ip_route 16.0.0.0/16 "$(vrf_name_from_id 1)" 2 1
set_ip_route 16.0.0.0/16 172.16.0.2 1

ip netns exec p0 ping -i0.01 -c3 -I 16.0.0.1 -n 16.1.0.1
ip netns exec p1 ping -i0.01 -c3 -I 16.1.0.1 -n 16.0.0.1
