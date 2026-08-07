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
	ip -n $ns route add default via fd00:ba4:$n::1 dev $p
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
pids=""
for _ in {0..20}; do
	ip netns exec n0 ping6 -q -W 1 -c 1 -n fd00:baa::1 &
	pids="$pids $!"
done
wait $pids || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmpv6 error rate limiting did not drop any packet"

# Test ICMPv6 input rate limiting
grcli stats reset
grcli graph config set icmp-rate 1

# Send a burst of pings to the router local address. Most of them should be
# rate limited.
ip netns exec n0 ping6 -w 1 -i 0.01 -c 50 -n fd00:ba4:0::1 || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmpv6 input rate limiting did not drop any packet"

grcli graph config set icmp-error-rate 0 icmp-rate 0

# Test per-interface ping-ignore flag
grcli interface set port p0 ping-ignore on
grcli stats reset
ip netns exec n0 ping6 -W 1 -c 3 -n fd00:ba4:0::1 || true
grcli -j stats show software brief pattern ping_ignored |
	jq -e '.ping_ignored > 0' ||
	fail "ping-ignore flag did not drop any echo request"
grcli interface set port p0 ping-ignore off
ip netns exec n0 ping6 -W 1 -c 1 -n fd00:ba4:0::1 ||
	fail "ping failed after disabling ping-ignore"

# Test per-interface err-ignore flag
grcli interface set port p0 err-ignore on
grcli stats reset
ip netns exec n0 ping6 -W 1 -c 3 -n fd00:baa::1 || true
grcli -j stats show software brief pattern error_ignored |
	jq -e '.error_ignored > 0' ||
	fail "err-ignore flag did not drop any ICMPv6 error"
grcli interface set port p0 err-ignore off
