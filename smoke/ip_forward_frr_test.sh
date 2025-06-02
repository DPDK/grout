#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

set -e

test_frr=true

. $(dirname $0)/_init.sh

tap_index=0
create_interface() {
	local p="$1"
	local mac="$2"

	ip link add v0-$p type veth peer name v1-$p
	grcli add interface port $p devargs net_tap$tap_index,iface=tap-$p,remote=v0-$p mac $mac

	local max_tries=5
	local count=0
	while vtysh -c "show interface $p" 2>&1 | grep -q "% Can't find interface"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Interface $p not found after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done

	tap_index=$((tap_index + 1))
}

set_ip_address() {
	local p="$1"
	local ip_cidr="$2"
	local max_tries=5
	local count=0

	vtysh <<-EOF
	configure terminal
	interface ${p}
	ip address ${ip_cidr}
	exit
EOF

	while ! grcli show ip address | grep -q "^${p}[[:space:]]\+${ip_cidr}$"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Ip address $ip_cidr not set after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done
}

set_ip_route() {
	local prefix="$1"
	local next_hop="$2"
	local max_tries=5
	local count=0

	vtysh <<-EOF
	configure terminal
	ip route ${prefix} ${next_hop}
	exit
EOF

	while ! grcli show ip route | grep -q "^0[[:space:]]\+${prefix}[[:space:]]\+${next_hop}[[:space:]]"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Route ${prefix} via ${next_hop} not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done
}

p0=${run_id}0
p1=${run_id}1

create_interface $p0 f0:0d:ac:dc:00:00
create_interface $p1 f0:0d:ac:dc:00:01

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

set_ip_address $p0 172.16.0.1/24
set_ip_address $p1 172.16.1.1/24
set_ip_route 16.0.0.0/16 172.16.0.2
set_ip_route 16.1.0.0/16 172.16.1.2

ip netns exec n-$p0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -n 16.0.0.1
ip netns exec n-$p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n-$p1 ping -i0.01 -c3 -n 172.16.0.2
ip netns exec n-$p0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec n-$p0 traceroute -N1 -n 16.1.0.1
ip netns exec n-$p1 traceroute -N1 -n 16.0.0.1
ip netns exec n-$p0 traceroute -N1 -n 172.16.1.2
ip netns exec n-$p1 traceroute -N1 -n 172.16.0.2
