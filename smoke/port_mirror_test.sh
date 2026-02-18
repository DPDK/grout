#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0
port_add p2 domain br0

# Create mirror session: mirror p0 ingress+egress to p2
grcli port-mirror set br0 1 dest p2 sources p0,p1
grcli port-mirror show br0 1 | grep -q "enabled: true" || fail "mirror not enabled"
grcli port-mirror show br0 1 | grep -q "direction: both" || fail "direction should be both"

# Reconfigure with ingress only
grcli port-mirror set br0 1 dest p2 sources p0 ingress
grcli port-mirror show br0 1 | grep -q "direction: ingress" || fail "direction should be ingress"

# Create RSPAN session
grcli port-mirror set br0 2 dest p2 sources p1 rspan 100
grcli port-mirror show br0 2 | grep -q "rspan_vlan: 100" || fail "RSPAN VLAN not set"

# Delete session
grcli port-mirror del br0 2
grcli port-mirror show br0 2 | grep -q "enabled: false" || fail "session 2 not deleted"

# Session 1 should still be active
grcli port-mirror show br0 1 | grep -q "enabled: true" || fail "session 1 disappeared"

# Delete remaining session
grcli port-mirror del br0 1

# Cleanup
grcli interface del br0
