#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable DAI with validation
grcli dai set br0 validate-src-mac validate-ip
grcli dai show br0 | grep -q "enabled: true" || fail "DAI not enabled"
grcli dai show br0 | grep -q "validate_src_mac: yes" || fail "src mac validation not set"
grcli dai show br0 | grep -q "validate_ip: yes" || fail "ip validation not set"
grcli dai show br0 | grep -q "validate_dst_mac: no" || fail "dst mac should be off"

# Reconfigure with all validations
grcli dai set br0 validate-src-mac validate-dst-mac validate-ip log
grcli dai show br0 | grep -q "validate_dst_mac: yes" || fail "dst mac not enabled"
grcli dai show br0 | grep -q "log_violations: yes" || fail "logging not enabled"

# Disable
grcli dai set br0 off
grcli dai show br0 | grep -q "enabled: false" || fail "DAI not disabled"

grcli interface del br0
