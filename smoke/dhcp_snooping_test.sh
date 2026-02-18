#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable DHCP snooping
grcli dhcp-snooping set br0 verify-mac max-bindings 100
grcli dhcp-snooping show br0 | grep -q "enabled: true" || fail "not enabled"
grcli dhcp-snooping show br0 | grep -q "verify_mac: yes" || fail "verify_mac not set"
grcli dhcp-snooping show br0 | grep -q "max_bindings: 100" || fail "max_bindings not set"

# Trust a port
grcli dhcp-snooping trust br0 p0 trust
grcli dhcp-snooping show br0 | grep -q "num_trusted_ports: 1" || fail "trusted port not added"

# Untrust
grcli dhcp-snooping trust br0 p0 untrust
grcli dhcp-snooping show br0 | grep -q "num_trusted_ports: 0" || fail "trusted port not removed"

# Disable
grcli dhcp-snooping set br0 off
grcli dhcp-snooping show br0 | grep -q "enabled: false" || fail "not disabled"

grcli interface del br0
