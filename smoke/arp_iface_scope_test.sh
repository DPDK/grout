#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Red Hat, Inc.
#
# Two grout ports share one L2 domain (Linux bridge) with distinct IPs.
# ARP replies must use the MAC of the interface that owns the target IP.
# Regression for dual-VF / same-VLAN topologies where a VRF-wide local-IP
# lookup would otherwise answer with the wrong interface MAC.

. $(dirname $0)/_init.sh

command -v arping || fail "arping (from iputils-arping / iputils) is not installed"

port_add p0
port_add p1

ip link add name br-arp type bridge
ip link set br-arp up
ip link set x-p0 master br-arp
ip link set x-p1 master br-arp
ip link set x-p0 up
ip link set x-p1 up

grcli address add 172.16.21.1/28 iface p0
grcli address add 172.16.21.19/28 iface p1

mac0=$(grcli -j mac show iface p0 | jq -r '.[] | select(.primary == true) | .mac')
mac1=$(grcli -j mac show iface p1 | jq -r '.[] | select(.primary == true) | .mac')
[ -n "$mac0" ] && [ -n "$mac1" ] || fail "failed to read primary MACs"
[ "$mac0" != "$mac1" ] || fail "expected distinct MACs on p0 and p1"

netns_add peer
ip link add veth-peer type veth peer name veth-br
ip link set veth-br master br-arp
ip link set veth-br up
ip link set veth-peer netns peer
ip -n peer link set lo up
ip -n peer link set veth-peer up
ip -n peer addr add 172.16.21.10/28 dev veth-peer

# Happy path: each IP resolves to the owning interface MAC.
reply=$(ip netns exec peer arping -c1 -w2 -I veth-peer 172.16.21.1) \
	|| fail "ARP for p0 address failed"
echo "$reply" | grep -qi "$mac0" || fail "ARP for .1 did not return p0 MAC $mac0"
echo "$reply" | grep -qi "$mac1" && fail "ARP for .1 incorrectly returned p1 MAC $mac1"

reply=$(ip netns exec peer arping -c1 -w2 -I veth-peer 172.16.21.19) \
	|| fail "ARP for p1 address failed"
echo "$reply" | grep -qi "$mac1" || fail "ARP for .19 did not return p1 MAC $mac1"
echo "$reply" | grep -qi "$mac0" && fail "ARP for .19 incorrectly returned p0 MAC $mac0"

# With p0 down, p1 must not answer ARP for p0's address.
grcli interface set port p0 down
if ip netns exec peer arping -c3 -w1 -I veth-peer 172.16.21.1; then
	fail "got ARP reply for p0 address while p0 was down (p1 must not reply)"
fi

grcli interface set port p0 up
# Allow the port to come back before retrying.
sleep 0.5
ip netns exec peer arping -c1 -w2 -I veth-peer 172.16.21.1 \
	|| fail "ARP for p0 address failed after p0 up"

# Symmetrically: with p1 down, p0 must not answer for p1's address.
grcli interface set port p1 down
if ip netns exec peer arping -c3 -w1 -I veth-peer 172.16.21.19; then
	fail "got ARP reply for p1 address while p1 was down (p0 must not reply)"
fi

grcli interface set port p1 up
sleep 0.5
ip netns exec peer arping -c1 -w2 -I veth-peer 172.16.21.19 \
	|| fail "ARP for p1 address failed after p1 up"
