#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add fd00:ba4:0::1/64 iface p0
grcli address add fd00:ba4:1::1/64 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add fd00:ba4:$n::2/64 dev $p
	ip -n $ns route add fd00:ba4::/62 via fd00:ba4:$n::1 dev $p
done

grcli ping fd00:ba4:0::2 count 10 delay 100
grcli ping fd00:ba4:1::2 count 3 delay 10

# Expect this test to fail
grcli ping fd00:baa::1 count 1 && fail "ping to unknown route succeeded"
grcli ping fd00:ba4:1::3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute fd00:ba4:1::2

# Test ICMPv6 error rate limiting
grcli stats reset
grcli graph config set icmp-error-rate 1
# Send a burst of pings to a non-routable destination to trigger ICMPv6 dest
# unreachable errors. Most of them should be rate limited.
ip netns exec n0 ping6 -i 0.01 -W 1 -c 20 -n fd00:baa::1 || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmpv6 error rate limiting did not drop any packet"

# Test ICMPv6 input rate limiting
grcli stats reset
grcli graph config set icmp-rate 1
# Send a burst of pings to the router local address. Most of them should be
# rate limited.
ip netns exec n0 ping6 -W 1 -i 0.01 -c 50 -n fd00:ba4:0::1 || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmpv6 input rate limiting did not drop any packet"

# Disable rate limiting to avoid interfering with other tests
grcli graph config set icmp-error-rate 0 icmp-rate 0
