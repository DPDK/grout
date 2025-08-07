#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

. $(dirname $0)/_init_frr.sh

p0=${run_id}0
p1=${run_id}1

create_interface $p0 f0:0d:ac:dc:00:00 1
create_interface $p1 f0:0d:ac:dc:00:01 2

for n in 0 1; do
	p=$run_id$n
	netns_add n-$p
	ip link set v1-$p netns n-$p
	ip -n n-$p link set v1-$p address ba:d0:ca:ca:00:0$n
	ip -n n-$p link set v1-$p up
	ip -n n-$p link set lo up
	ip -n n-$p addr add 172.16.$n.2/24 dev v1-$p
	ip -n n-$p addr add 16.$n.0.1/16 dev lo
	ip -n n-$p route add default via 172.16.$n.1
	ip -n n-$p addr show
done

set_ip_address $p0 172.16.0.1/24 1
set_ip_address $p1 172.16.1.1/24 2

set_ip_route 16.0.0.0/16 172.16.0.2 2 1
set_ip_route 16.1.0.0/16 172.16.1.2 1 2

ip netns exec n-$p0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec n-$p0 ping -i0.01 -c3 -I 16.0.0.1 -n 16.1.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -I 16.1.0.1 -n 16.0.0.1
