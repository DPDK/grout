#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable storm control with rate limits
grcli storm-control set p0 broadcast 10000 multicast 5000
grcli storm-control show p0 | grep -q "enabled: true" || fail "storm control not enabled"
grcli storm-control show p0 | grep -q "broadcast: 10000" || fail "broadcast rate not set"
grcli storm-control show p0 | grep -q "multicast: 5000" || fail "multicast rate not set"
grcli storm-control show p0 | grep -q "status: active" || fail "should be active"

# Reconfigure with pps mode and shutdown
grcli storm-control set p0 broadcast 1000 pps shutdown threshold 3
grcli storm-control show p0 | grep -q "shutdown_on_violation: yes" || fail "shutdown not set"
grcli storm-control show p0 | grep -q "violation_threshold: 3" || fail "threshold not set"

# Configure second port
grcli storm-control set p1 broadcast 20000 unknown-unicast 8000
grcli storm-control show p1 | grep -q "enabled: true" || fail "p1 storm control not enabled"

# Disable storm control
grcli storm-control set p0 off
grcli storm-control show p0 | grep -q "enabled: false" || fail "storm control not disabled"

# Re-enable
grcli storm-control set p0 broadcast 5000
grcli storm-control show p0 | grep -q "enabled: true" || fail "storm control not re-enabled"

# Reenable command (for shutdown recovery)
grcli storm-control reenable p0

# Cleanup
grcli interface del br0
