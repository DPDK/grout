#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Christophe Fontaine

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.2.1/24 iface p0
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	ip -n $ns route add default via 172.16.$n.1
done

set -m

grcli ping 172.16.0.2 count 10 delay 100 &
grcli ping 172.16.1.2 count 3 delay 10

fg

# Expect this test to fail
grcli ping 1.1.1.1 count 1 && fail "ping to unknown route succeeded"
grcli ping 172.16.1.3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute 172.16.0.2

# Test ICMP error rate limiting
grcli stats reset
grcli graph config set icmp-error-rate 1

# Send a burst of pings to a non-routable destination to trigger ICMP dest
# unreachable errors. Most of them should be rate limited.
pids=""
for _ in {0..20}; do
	ip netns exec n0 ping -q -W 1 -c 1 -n 1.1.1.1 &
	pids="$pids $!"
done
wait $pids || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmp error rate limiting did not drop any packet"

# Test ICMP input rate limiting
grcli stats reset
grcli graph config set icmp-rate 1

# Send a burst of pings to the router local address. Most of them should be
# rate limited.
ip netns exec n0 ping -w 1 -i 0.01 -c 50 -n 172.16.0.1 || true
grcli -j stats show software brief pattern error_rate_limited |
	jq -e '.error_rate_limited > 0' ||
	fail "icmp input rate limiting did not drop any packet"

grcli graph config set icmp-error-rate 0 icmp-rate 0

# Test per-interface ping-ignore flag
grcli interface set port p0 ping-ignore on
grcli stats reset
ip netns exec n0 ping -W 1 -c 3 -n 172.16.0.1 || true
grcli -j stats show software brief pattern ping_ignored |
	jq -e '.ping_ignored > 0' ||
	fail "ping-ignore flag did not drop any echo request"
grcli interface set port p0 ping-ignore off
ip netns exec n0 ping -W 1 -c 1 -n 172.16.0.1 ||
	fail "ping failed after disabling ping-ignore"

# Test per-interface err-ignore flag
grcli interface set port p0 err-ignore on
grcli stats reset
ip netns exec n0 ping -W 1 -c 3 -n 1.1.1.1 || true
grcli -j stats show software brief pattern error_ignored |
	jq -e '.error_ignored > 0' ||
	fail "err-ignore flag did not drop any ICMP error"
grcli interface set port p0 err-ignore off
