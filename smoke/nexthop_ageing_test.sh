#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

check_nexthop() {
	local ip="$1"
	local expect_reacheable="$2"
	local attempts=25
	while [ "$attempts" -gt 0 ]; do
		grcli -j nexthop show internal type l3 | jq -e --arg a "$ip" '.[] | select(.addr | contains($a)) | select(.state == "reachable")'
		local result=$?

		if [ "$expect_reacheable" = "true" ] && [ "$result" -eq 0 ]; then
			return 0
		fi
		if [ "$expect_reacheable" = "false" ] && [ "$result" -ne 0 ]; then
			return 0
		fi

		sleep 0.2
		attempts=$((attempts - 1))
	done

	return 1
}

wait_nexthop_gone() {
	local ip="$1"
	local attempts=50
	while [ "$attempts" -gt 0 ]; do
		if grcli -j nexthop show type l3 |
			jq -e --arg a "$ip" '[.[] | select(.addr == $a)] | length == 0'; then
			return 0
		fi
		sleep 0.2
		attempts=$((attempts - 1))
	done
	return 1
}

grcli nexthop config set lifetime 2 unreachable 1 ucast-probes 1 bcast-probes 1
port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli address add fd00:1::1/64 iface p0

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	ip -n $ns route add default via 172.16.$n.1
done

ip -n n0 -6 addr add fd00:1::2/64 dev x-p0
ip netns exec n0 ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0

ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n1 ping -i0.01 -c3 -n 172.16.0.2
grcli route add 10.77.1.0/24 via 172.16.1.2

grcli nexthop show
# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

grcli nexthop show

# ensure that nexthops are still reachable
check_nexthop '172.16.0.2' true || fail "nexthop 172.16.0.2 should be reachable"
check_nexthop '172.16.1.2' true || fail "nexthop 172.16.1.2 should be reachable"

# ensure addresses were not destroyed
grcli -j address show | jq -e '.[] | select(.iface == "p0" and .address == "172.16.0.1/24")' || fail "addresses were destroyed"
grcli -j address show | jq -e '.[] | select(.iface == "p1" and .address == "172.16.1.1/24")' || fail "addresses were destroyed"

# force interfaces down so that linux does not reply to ARP requests anymore
ip -n n0 link set x-p0 down
ip -n n1 link set x-p1 down

# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

# ensure that learned neighbors and their host routes have been removed
wait_nexthop_gone '172.16.0.2' || fail "nexthop 172.16.0.2 should be destroyed"
wait_nexthop_gone 'fd00:1::2' || fail "nexthop fd00:1::2 should be destroyed"
grcli -j route get 172.16.0.2 | jq -e '.nexthop.addr == "172.16.0.1/24"' || fail "learned IPv4 host route was not removed"
grcli -j route get 172.16.1.2 | jq -e '.nexthop.addr == "172.16.1.1/24"' || fail "referenced learned IPv4 host route was not removed"
grcli -j route get fd00:1::2 | jq -e '.nexthop.addr == "fd00:1::1/64"' || fail "learned IPv6 host route was not removed"

# An external route keeps the unreachable nexthop alive.
grcli -j route show | jq -e '.[] | select(.destination == "10.77.1.0/24")' || fail "external route was removed with host route"
grcli -j nexthop show type l3 | jq -e '.[] | select(.addr == "172.16.1.2" and .state == "failed")' || fail "unreachable nexthop was removed with its external route"
grcli route del 10.77.1.0/24
wait_nexthop_gone '172.16.1.2' || fail "learned neighbor should be destroyed after its last route is removed"

# ensure addresses were not destroyed
grcli -j address show | jq -e '.[] | select(.iface == "p0" and .address == "172.16.0.1/24")' || fail "addresses were destroyed"
grcli -j address show | jq -e '.[] | select(.iface == "p1" and .address == "172.16.1.1/24")' || fail "addresses were destroyed"
