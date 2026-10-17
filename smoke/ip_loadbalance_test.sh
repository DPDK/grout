#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

#
#                  p0 (.0.2)     |               |
# 192.200.0.2  lo             n0 | --- grout --- | n1  p2  172.16.2.2
#                  p1 (.1.2)     |               |
#
. $(dirname $0)/_init.sh

port_add p0
port_add p1
port_add p2

netns_add n0
move_to_netns x-p0 n0
move_to_netns x-p1 n0
ip -n n0 addr add 192.200.0.2/24 dev lo
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 addr add 172.16.1.2/24 dev x-p1
ip -n n0 nexthop add id 1601 via 172.16.0.1 dev x-p0
ip -n n0 nexthop add id 1611 via 172.16.1.1 dev x-p1
ip -n n0 nexthop add id 1620 group 1601/1611
ip -n n0 route add 172.16.2.0/24 nhid 1620

netns_add n1
move_to_netns x-p2 n1
ip -n n1 addr add 172.16.2.2/24 dev x-p2
ip -n n1 route add default via 172.16.2.1

grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli address add 172.16.2.1/24 iface p2

# Add ECMP route
grcli nexthop add l3 iface p0 address 172.16.0.2 id 100
grcli nexthop add l3 iface p1 address 172.16.1.2 id 101
grcli nexthop add group id 10 member 100 member 101
grcli route add 192.200.0.0/24 via id 10

# Locally generated ICMP requests
grcli ping 192.200.0.2 count 1 ident 1 delay 10
grcli ping 192.200.0.2 count 1 ident 2 delay 10

# Externally generated ICMP requests
ip netns exec n0 ping -i0.01 -c3 -n 192.200.0.2

# Distinct flows entering through a port without RSS must spread across both
# group members instead of all collapsing onto one nexthop.
ip netns exec n0 ping -i0.01 -c1 -W1 -n -I x-p0 172.16.0.1
ip netns exec n0 ping -i0.01 -c1 -W1 -n -I x-p1 172.16.1.1

rx_pkts() {
	ip -n n0 -j -s link show "$1" | jq '.[0].stats64.rx.packets'
}
p0_before=$(rx_pkts x-p0)
p1_before=$(rx_pkts x-p1)
ip netns exec n1 bash -c \
	'for i in $(seq 64); do echo flow > /dev/udp/192.200.0.2/7777; done'
sleep 0.3
p0_delta=$(($(rx_pkts x-p0) - p0_before))
p1_delta=$(($(rx_pkts x-p1) - p1_before))
[ $((p0_delta + p1_delta)) -ge 32 ] ||
	fail "expected forwarded UDP flows on the members, saw $((p0_delta + p1_delta))"
[ "$p0_delta" -ge 8 ] ||
	fail "member p0 carried $p0_delta of 64 distinct flows"
[ "$p1_delta" -ge 8 ] ||
	fail "member p1 carried $p1_delta of 64 distinct flows"
