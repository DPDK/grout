#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy

#
#          p0 (172.16.0.1) --- x-p0 (172.16.0.2)
# grout                                            n0
#          p1 (172.16.1.1) --- x-p1 (172.16.1.2)
#
# Check that traffic injected from Linux through the TUN loopback is spread
# over the members of a nexthop group. Without a flow hash, hash.rss holds
# whatever the previous user of the mbuf left there and every flow ends up on
# the same member.
#
. $(dirname $0)/_init.sh

port_add p0
port_add p1

netns_add n0
move_to_netns x-p0 n0
move_to_netns x-p1 n0
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 addr add 172.16.1.2/24 dev x-p1

grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

# Static MACs, so that the members never need to be resolved by ARP.
mac0=$(ip -n n0 -br link show x-p0 | awk '{print $3}')
mac1=$(ip -n n0 -br link show x-p1 | awk '{print $3}')
grcli nexthop add l3 iface p0 address 172.16.0.2 mac $mac0 id 100
grcli nexthop add l3 iface p1 address 172.16.1.2 mac $mac1 id 101
grcli nexthop add group id 10 member 100 member 101
grcli route add 192.200.0.0/24 via id 10

# Count the echo requests reaching each member link. --immediate-mode is
# required, otherwise libpcap keeps the packets in its ring and tcpdump is
# killed before it ever processes them.
probe() { # $@: destinations to ping
	local cap0 cap1 pid0 pid1
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

	for d in "$@"; do
		ping -c1 -W1 -n "$d" >/dev/null 2>&1 || true
	done

	kill $pid0 $pid1 2>/dev/null || true
	wait $pid0 $pid1 2>/dev/null || true
	c0=$(grep -c "echo request" "$cap0" || true)
	c1=$(grep -c "echo request" "$cap1" || true)
	rm -f "$cap0" "$cap1"
}

# The destinations must stay unanswered on purpose: a reply makes grout learn
# the sender as a neighbour and insert an internal /32 for it
# (arp_probe_input_cb), which is more specific than the group route and takes
# the traffic out of the group entirely.
echo "### same flow, 10 probes: all of them on a single member"
probe 192.200.0.10 192.200.0.10 192.200.0.10 192.200.0.10 192.200.0.10 \
      192.200.0.10 192.200.0.10 192.200.0.10 192.200.0.10 192.200.0.10
echo "p0=$c0 p1=$c1"
[ $(( c0 + c1 )) = 10 ] || fail "expected 10 echo requests, got $(( c0 + c1 ))"
[ "$c0" = 0 ] || [ "$c1" = 0 ] || fail "a single flow was spread over both members"

echo "### 16 distinct destinations: both members used"
dests=
for i in $(seq 16); do dests="$dests 192.200.0.$((100 + i))"; done
probe $dests
echo "p0=$c0 p1=$c1"
[ $(( c0 + c1 )) = 16 ] || fail "expected 16 echo requests, got $(( c0 + c1 ))"
[ "$c0" -gt 0 ] && [ "$c1" -gt 0 ] || fail "nexthop group did not spread injected traffic"
