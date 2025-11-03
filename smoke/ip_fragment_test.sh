#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Anthony Harivel
# Test IPv4 fragmentation

. $(dirname $0)/_init.sh

port_add p0
# Set smaller MTU on p1 (egress) to force fragmentation
port_add p1 mtu 1280
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	ip link set $p mtu 1500
	ip link set $p netns $ns
	ip -n $ns link set $p up
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	ip -n $ns route add default via 172.16.$n.1
	# Clear PMTU cache to ensure kernel uses interface MTU
	ip -n $ns route flush cache
done

# Test 1: Ping with default packet size (should work without fragmentation)
ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2

# Test 2: Large packet with DF flag set (should get ICMP fragmentation needed error)
# Send 1260-byte packet with DF=1 (Don't Fragment)
# Packet size: 1260 + 8 (ICMP) + 20 (IP) = 1288 bytes
# Fits in p0 MTU (1500) but exceeds p1 MTU (1280)
# Expected: ICMP Type 3 Code 4 (Fragmentation Needed and DF Set)
ip netns exec n0 ping -i0.01 -c3 -s 1260 -M do -n 172.16.1.2 && fail "ping with DF flag should have failed"

# Test 3: Large packet without DF flag (should fragment and succeed)
# Send 1260-byte packet with DF=0 (fragmentation allowed)
# Packet size: 1260 + 8 (ICMP) + 20 (IP) = 1288 bytes
# Fits in p0 MTU (1500) but needs fragmentation for p1 MTU (1280)
# Expected: Packet is fragmented into 2 fragments (1276 + 32 bytes) and ping succeeds
ip netns exec n0 ip route flush cache
ip netns exec n0 ping -i0.01 -c3 -s 1260 -M dont -n 172.16.1.2
