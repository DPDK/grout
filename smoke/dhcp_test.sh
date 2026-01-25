#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Anthony Harivel

. $(dirname $0)/_init.sh

command -v dnsmasq || fail "dnsmasq is not installed"

netns_add dhcp-server

port_add p0

move_to_netns x-p0 dhcp-server
ip -n dhcp-server addr add 192.168.100.1/24 dev x-p0

cat > $tmp/dnsmasq.conf <<EOF
# DHCP server configuration
interface=x-p0
bind-interfaces
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=option:router,192.168.100.1
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
dhcp-option=option:domain-name,test.local
dhcp-authoritative
log-dhcp
no-daemon
EOF

ip netns exec dhcp-server dnsmasq \
	--conf-file=$tmp/dnsmasq.conf \
	--log-facility=$tmp/dnsmasq.log \
	--pid-file=$tmp/dnsmasq.pid &

cat >> $tmp/cleanup <<EOF
[ -f $tmp/dnsmasq.pid ] && kill \$(cat $tmp/dnsmasq.pid) 2>/dev/null || true
EOF

# Wait for dnsmasq to start
sleep 1

# Enable DHCP on grout interface
grcli dhcp enable p0

# Wait for DHCP to acquire lease (adjust timeout as needed)
sleep 5

# Verify default route was added
grcli route show | grep -q "0.0.0.0/0.*192.168.100.1" || fail "DHCP did not add default route"

# Verify DHCP assigned an address by checking the /24 route exists
grcli route show | grep -q "192.168.100.0/24" || fail "DHCP did not assign IP address"

# Query DHCP status via API
echo "=== DHCP Client Status ==="
grcli dhcp show
grcli dhcp show | grep -q "p0" || fail "DHCP status not available"
grcli dhcp show | grep -q "BOUND" || fail "DHCP client not in BOUND state"

# Test DHCP release/disable
grcli dhcp disable p0

# Verify default route was removed
! grcli route show | grep -q "0.0.0.0/0.*192.168.100.1" || fail "DHCP route not removed after disable"

# Verify DHCP client is no longer active
! grcli dhcp show | grep -q "p0" || fail "DHCP client still active after disable"

echo "DHCP smoke test passed!"
