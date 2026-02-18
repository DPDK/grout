#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

grcli interface add bridge br0
port_add p0 domain br0

# Enable LLDP
grcli lldp set br0 tx-interval 30 ttl 120
grcli lldp show br0 | grep -q "enabled: true" || fail "LLDP not enabled"
grcli lldp show br0 | grep -q "tx_interval: 30" || fail "tx_interval not set"
grcli lldp show br0 | grep -q "ttl: 120" || fail "ttl not set"
grcli lldp show br0 | grep -q "neighbors: 0" || fail "should have 0 neighbors"

# Reconfigure
grcli lldp set br0 tx-interval 10 ttl 60
grcli lldp show br0 | grep -q "tx_interval: 10" || fail "tx_interval not updated"
grcli lldp show br0 | grep -q "ttl: 60" || fail "ttl not updated"

# Disable
grcli lldp set br0 off
grcli lldp show br0 | grep -q "enabled: false" || fail "LLDP not disabled"

grcli interface del br0
