#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

echo "=== L2 Bridge Smoke Test ==="

# Create ports
port_add p0
port_add p1
port_add p2

# Create bridge domain
echo "Creating bridge domain..."
grcli bridge add testbr aging_time 300 max_mac_count 1024

# Add interfaces to bridge
echo "Adding interfaces to bridge..."
grcli interface set p0 mode bridge testbr
grcli interface set p1 mode bridge testbr
grcli interface set p2 mode bridge testbr

# Verify bridge configuration
echo "Bridge configuration & members"
grcli bridge show testbr

# Create bridge interface for L3 integration
echo "Creating bridge interface..."
grcli interface add bridge br1 bridge testbr
grcli interface set br1 mode bridge testbr

# Assign IP address to bridge interface
echo "Assigning IP to bridge interface..."
grcli address add 192.168.100.1/24 iface br1

# Set up test namespaces connected to bridge ports
echo "Setting up test namespaces..."
for n in 0 1 2; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	ip link set $p netns $ns
	ip -n $ns link set $p up
	ip -n $ns addr add 192.168.100.$((n+10))/24 dev $p
	ip -n $ns route add default via 192.168.100.1
done

# Test static MAC entry
echo "Adding static MAC entry..."
# Get MAC address of n0 interface
MAC0=$(ip netns exec n0 cat /sys/class/net/x-p0/address)
grcli bridge mac add br testbr mac $MAC0 iface p0 static

echo "MAC table after adding static entry:"
grcli bridge mac list testbr

# Wait a moment for interfaces to come up
sleep 2

echo "Testing L2 connectivity (same subnet)..."
# Test L2 connectivity between hosts in same bridge
ip netns exec n0 ping -i0.01 -c3 -W1 -n 192.168.100.11 || echo "L2 ping n0->n1 failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 192.168.100.12 || echo "L2 ping n1->n2 failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 192.168.100.10 || echo "L2 ping n2->n0 failed"

echo "Testing L3 connectivity (from bridge interface)..."
grcli ping 192.168.100.10 count 3 delay 10

echo "Testing L3 connectivity (to bridge interface)..."
# Test L3 connectivity to bridge interface
ip netns exec n0 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n0->bridge failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n1->bridge failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n2->bridge failed"

# Check MAC learning
echo "MAC table entries:"
grcli bridge mac list testbr

# Test MAC flush
echo "Flushing dynamic MAC entries..."
grcli bridge mac flush br testbr dynamic_only

echo "MAC table after flush:"
grcli bridge mac list testbr

# Test bridge removal (cleanup)
echo "Cleaning up..."
grcli interface set p0 mode l3
grcli interface set p1 mode l3
grcli interface set p2 mode l3
grcli bridge del testbr

echo "=== L2 Bridge Smoke Test Complete ==="
