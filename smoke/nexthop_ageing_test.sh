#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

check_nexthop() {
	local ip="$1"
	local expect_reacheable="$2"
	local timeout=5
	for i in $(seq 1 $timeout); do
		grcli nexthop show internal | grep -qE "$ip.+reachable";
		local result=$?

		if [ "$expect_reacheable" = "true" ] && [ "$result" -eq 0 ]; then
			return 0
		fi
		if [ "$expect_reacheable" = "false" ] && [ "$result" -ne 0 ]; then
			return 0
		fi

		sleep 1
	done

	return 1
}

p0=${run_id}0
p1=${run_id}1

grcli nexthop config set lifetime 2 unreachable 1 ucast-probes 1 bcast-probes 1

for n in 0 1; do
	p=$run_id$n
	port_add $p
	grcli address add 172.16.$n.1/24 iface $p
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2

grcli nexthop show
# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

grcli nexthop show

# ensure that nexthops are still reachable
check_nexthop '172\.16\.0\.2' true || fail "nexthop 172.16.0.2 should be reachable"
check_nexthop '172\.16\.1\.2' true || fail "nexthop 172.16.1.2 should be reachable"

# ensure addresses were not destroyed
grcli address show | grep -E "^$p0[[:space:]]+172\\.16\\.0\\.1/24$" || fail "addresses were destroyed"
grcli address show | grep -E "^$p1[[:space:]]+172\\.16\\.1\\.1/24$" || fail "addresses were destroyed"

# force interfaces down so that linux does not reply to ARP requests anymore
ip -n $p0 link set $p0 down
ip -n $p1 link set $p1 down

# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

# ensure that nexthops have been aged out and destroyed
check_nexthop '172\.16\.0\.2' false || fail "nexthop 172.16.0.2 should be destroyed"
check_nexthop '172\.16\.1\.2' false || fail "nexthop 172.16.1.2 should be destroyed"

# ensure addresses were not destroyed
grcli address show | grep -E "^$p0[[:space:]]+172\\.16\\.0\\.1/24$" || fail "addresses were destroyed"
grcli address show | grep -E "^$p1[[:space:]]+172\\.16\\.1\\.1/24$" || fail "addresses were destroyed"
