#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

set -e
zebra=$(PATH="$1/frr_install/sbin:$1/frr_install/bin:$PATH" command -v zebra)
frr_version=$($zebra --version | sed -En 's/zebra version //p')
min_version=$(printf '%s\n%s\n' "$frr_version" "10.8.0" | sort -V | head -n1)
if ! [ "$min_version" = "10.8.0" ]; then
	echo "$0: FRR $frr_version does not support per-nexthop encap source"
	exit 125
fi

. $(dirname $0)/_init_frr.sh

create_interface p0
create_interface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
done
ip -n n0 addr add 192.168.61.2/24 dev x-p0
ip -n n1 addr add fd00:102::2/32 dev x-p1

set_ip_address p0 192.168.61.1/24
set_ip_address p1 fd00:102::1/32

#
# network layout:
#  (client) p0(netns) <--> p0 <grout> p1 <--->  p1(netns)
#       ipv4 ---------------|        srv6        |-- ipv4
#
# test case:
#   - configure an SRv6 route with an explicit encap source via FRR
#   - verify grout uses the per-nexthop source instead of the global one
#

# only linux's p1 will see srv6
ip netns exec n1 sysctl -w net.ipv6.conf.x-p1.seg6_enabled=1
ip netns exec n1 sysctl -w net.ipv6.conf.x-p1.forwarding=1

# client default route
ip -n n0 route add default via 192.168.61.1 dev x-p0

# linux decap and reply network
ip -n n1 -6 route add fd00:202:200:: \
	encap seg6local action End.DX4 nh4 192.168.60.1 count dev x-p1
ip -n n1 addr add 192.168.60.1/24 dev x-p1
ip -n n1 route add 192.168.61.0/24 \
	encap seg6 mode encap segs fd00:202:100:: dev x-p1
ip -n n1 -6 route add fd00:202::/32 via fd00:102::1 dev x-p1

# grout decap localsid
set_srv6_localsid locator_grout fd00:202 fd00:202:100::

# underlay route
set_ip_route fd00:202::/32 fd00:102::2

# SRv6 route with explicit per-nexthop encap source via FRR
encap_src=fd00:102::42
set_srv6_route --encap-src $encap_src 192.168.0.0/16 p1 fd00:202:200::

# capture and verify the outer source address
ip netns exec n1 timeout 5 tcpdump -c1 -nn -l \
	"ip6 src $encap_src" -i x-p1 > $tmp/tcpdump.out 2>&1 &
tcpdump_pid=$!
sleep 1

ip netns exec n0 ping -i0.01 -c3 -n 192.168.60.1
wait $tcpdump_pid || true

grep -q "$encap_src" $tmp/tcpdump.out \
	|| fail "encapsulated packet did not use per-nexthop encap_src $encap_src"
