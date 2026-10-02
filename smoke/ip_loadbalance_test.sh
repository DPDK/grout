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

# Transit traffic must be spread over both group members. The destinations are
# left unanswered on purpose: a reply would make grout learn the sender and
# insert a host route for it, which is more specific than the group route and
# would take the traffic out of the group.
#
# Resolve both members first so that no probe is lost waiting for ARP.
ping -c1 -W1 -n 172.16.0.2 >/dev/null 2>&1 || true
ping -c1 -W1 -n 172.16.1.2 >/dev/null 2>&1 || true

cap0=$(mktemp)
cap1=$(mktemp)
ip netns exec n0 timeout 30 tcpdump --immediate-mode -pnnli x-p0 icmp >"$cap0" 2>&1 &
pid0=$!
ip netns exec n0 timeout 30 tcpdump --immediate-mode -pnnli x-p1 icmp >"$cap1" 2>&1 &
pid1=$!
for _ in $(seq 50); do
	if grep -q "listening on" "$cap0" && grep -q "listening on" "$cap1"; then
		break
	fi
	sleep 0.1
done

for i in $(seq 16); do
	ip netns exec n1 ping -c1 -W1 -n 192.200.0.$((100 + i)) >/dev/null 2>&1 || true
done

kill $pid0 $pid1 2>/dev/null || true
wait $pid0 $pid1 2>/dev/null || true
c0=$(grep -c "echo request" "$cap0" || true)
c1=$(grep -c "echo request" "$cap1" || true)
rm -f "$cap0" "$cap1"

echo "group members: p0=$c0 p1=$c1"
[ $((c0 + c1)) = 16 ] || fail "expected 16 requests through the group, got $((c0 + c1))"
[ "$c0" -gt 0 ] && [ "$c1" -gt 0 ] || fail "nexthop group did not spread transit traffic"
