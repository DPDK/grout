#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0
port_add p2 domain br0

# Enable VLAN filtering
grcli vlan-filtering set br0 on
grcli vlan-filtering show br0 | grep -q "enabled" || fail "VLAN filtering not enabled"

# Configure access port
grcli vlan-filtering port set br0 p0 access 100
grcli vlan-filtering port show br0 p0 | grep -q "mode: access" || fail "p0 not in access mode"
grcli vlan-filtering port show br0 p0 | grep -q "access_vlan: 100" || fail "p0 access VLAN not 100"

# Configure trunk port
grcli vlan-filtering port set br0 p1 trunk native 1 allowed 10,20,30,100
grcli vlan-filtering port show br0 p1 | grep -q "mode: trunk" || fail "p1 not in trunk mode"
grcli vlan-filtering port show br0 p1 | grep -q "native_vlan: 1" || fail "p1 native VLAN not 1"

# Configure hybrid port
grcli vlan-filtering port set br0 p2 hybrid native 1 allowed 10,20
grcli vlan-filtering port show br0 p2 | grep -q "mode: hybrid" || fail "p2 not in hybrid mode"

# Reconfigure access port to different VLAN
grcli vlan-filtering port set br0 p0 access 200
grcli vlan-filtering port show br0 p0 | grep -q "access_vlan: 200" || fail "p0 access VLAN not updated"

# Configure trunk with all VLANs (no allowed list)
grcli vlan-filtering port set br0 p1 trunk
grcli vlan-filtering port show br0 p1 | grep -q "mode: trunk" || fail "p1 trunk reconfigure failed"

# Disable VLAN filtering
grcli vlan-filtering set br0 off
grcli vlan-filtering show br0 | grep -q "disabled" || fail "VLAN filtering not disabled"

# Re-enable and verify state is fresh
grcli vlan-filtering set br0 on
grcli vlan-filtering show br0 | grep -q "enabled" || fail "VLAN filtering not re-enabled"

# Default should be access mode VLAN 1
grcli vlan-filtering port show br0 p0 | grep -q "mode: access" || fail "p0 not reset to access"
grcli vlan-filtering port show br0 p0 | grep -q "access_vlan: 1" || fail "p0 not reset to VLAN 1"

# Cleanup
grcli interface del br0
