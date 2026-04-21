#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 David Marchand

. $(dirname $0)/_init.sh

# Create a test port
grcli interface add port p0 devargs net_tap0,iface=x-p0

# Test adding secondary MAC addresses
mac1="02:00:00:00:00:01"
mac2="02:00:00:00:00:02"
mac3="02:00:00:00:00:03"

echo "Adding secondary MAC addresses..."
grcli mac add "$mac1" iface p0
grcli mac add "$mac2" iface p0
grcli mac add "$mac3" iface p0

# List all MAC addresses
echo "Listing MAC addresses on p0:"
grcli mac show iface p0

# Verify MAC addresses are present (3 secondary + 1 primary = 4 total)
count=$(grcli -j mac show iface p0 | jq 'length')
if [ "$count" -ne 4 ]; then
	fail "Expected 4 MACs (1 primary + 3 secondary), found $count"
fi

# Verify specific MAC is present with refcnt 1
refcnt=$(grcli -j mac show iface p0 | jq -r --arg mac "$mac1" '.[] | select(.mac == $mac) | .refcnt')
if [ "$refcnt" -ne 1 ]; then
	fail "MAC $mac1 should have refcnt 1, found $refcnt"
fi

# Test deleting a MAC address
echo "Deleting MAC $mac2..."
grcli mac del "$mac2" iface p0

# Verify MAC was deleted (1 primary + 2 secondary = 3 total)
count=$(grcli -j mac show iface p0 | jq 'length')
if [ "$count" -ne 3 ]; then
	fail "Expected 3 MACs (1 primary + 2 secondary) after deletion, found $count"
fi

# Verify deleted MAC is gone
if grcli -j mac show iface p0 | jq -e --arg mac "$mac2" '.[] | select(.mac == $mac)' 2>/dev/null; then
	fail "MAC $mac2 should have been deleted"
fi

# Test adding duplicate MAC (should succeed, refcount should increase)
echo "Adding duplicate MAC $mac1..."
grcli mac add "$mac1" iface p0

# Still should have 3 entries (1 primary + 2 secondary, refcount increased)
count=$(grcli -j mac show iface p0 | jq 'length')
if [ "$count" -ne 3 ]; then
	fail "Expected 3 MACs (1 primary + 2 secondary) after duplicate add, found $count"
fi

# Verify refcnt increased to 2
refcnt=$(grcli -j mac show iface p0 | jq -r --arg mac "$mac1" '.[] | select(.mac == $mac) | .refcnt')
if [ "$refcnt" -ne 2 ]; then
	fail "MAC $mac1 should have refcnt 2 after duplicate add, found $refcnt"
fi

# Delete once, refcnt should decrease to 1
echo "Deleting MAC $mac1 (first time)..."
grcli mac del "$mac1" iface p0

count=$(grcli -j mac show iface p0 | jq 'length')
if [ "$count" -ne 3 ]; then
	fail "Expected 3 MACs (1 primary + 2 secondary) after first delete, found $count"
fi

refcnt=$(grcli -j mac show iface p0 | jq -r --arg mac "$mac1" '.[] | select(.mac == $mac) | .refcnt')
if [ "$refcnt" -ne 1 ]; then
	fail "MAC $mac1 should have refcnt 1 after first delete, found $refcnt"
fi

# Delete again, MAC should be removed
echo "Deleting MAC $mac1 (second time)..."
grcli mac del "$mac1" iface p0

count=$(grcli -j mac show iface p0 | jq 'length')
if [ "$count" -ne 2 ]; then
	fail "Expected 2 MACs (1 primary + 1 secondary) after second delete, found $count"
fi

# Verify mac1 is completely gone
if grcli -j mac show iface p0 | jq -e --arg mac "$mac1" '.[] | select(.mac == $mac)' 2>/dev/null; then
	fail "MAC $mac1 should have been completely removed"
fi

# Create VLAN interface to test MAC inheritance
echo "Creating VLAN interface..."
grcli interface add vlan p0.100 parent p0 vlan 100

# Add MAC to VLAN, should also be added to parent port
mac4="02:00:00:00:00:04"
grcli mac add "$mac4" iface p0.100

# Verify MAC is on VLAN
grcli -j mac show iface p0.100 | jq -e --arg mac "$mac4" '.[] | select(.mac == $mac)' \
	|| fail "MAC $mac4 not found on VLAN"

# List all MACs across all interfaces
echo "Listing all MAC addresses:"
grcli mac show

# Test error handling: try to add invalid MAC
if grcli mac add "invalid-mac" iface p0 2>/dev/null; then
	fail "Adding invalid MAC should have failed"
fi

# Test error handling: try to add MAC to non-existent interface
if grcli mac add "$mac1" iface nonexistent 2>/dev/null; then
	fail "Adding MAC to non-existent interface should have failed"
fi

# Test error handling: try to delete non-existent MAC
if grcli mac del "02:00:00:00:00:99" iface p0 2>/dev/null; then
	fail "Deleting non-existent MAC should have failed"
fi

echo "All MAC address tests passed"
