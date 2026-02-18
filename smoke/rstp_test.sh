#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable RSTP with default parameters
grcli rstp set br0 priority 32768 hello_time 2 forward_delay 15 max_age 20

# Verify RSTP status
grcli rstp show br0 | grep -q "enabled: true" || fail "RSTP not enabled"
grcli rstp show br0 | grep -q "priority: 32768" || fail "RSTP priority not set"
grcli rstp show br0 | grep -q "is_root: yes" || fail "should be root bridge"

# Configure port parameters
grcli rstp port set br0 p0 priority 128
grcli rstp port show br0 p0 | grep -q "priority: 128" || fail "priority not set"

grcli rstp port set br0 p1 path_cost 2000 root_guard
grcli rstp port show br0 p1 | grep -q "root_guard: yes" || fail "root_guard not set"
grcli rstp port show br0 p1 | grep -q "path_cost: 2000" || fail "path_cost not set"

# Disable RSTP
grcli rstp set br0 disable
grcli rstp show br0 | grep -q "enabled: false" || fail "RSTP not disabled"

# Re-enable with different priority
grcli rstp set br0 priority 4096

grcli rstp show br0 | grep -q "enabled: true" || fail "RSTP not re-enabled"
grcli rstp show br0 | grep -q "priority: 4096" || fail "RSTP priority not updated"

# Cleanup
grcli interface del br0
