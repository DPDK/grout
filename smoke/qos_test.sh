#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable QoS with strict scheduling
grcli qos set p0 strict trust-cos port-rate 100000
grcli qos show p0 | grep -q "enabled: true" || fail "QoS not enabled"
grcli qos show p0 | grep -q "scheduler: strict" || fail "scheduler not strict"
grcli qos show p0 | grep -q "trust_cos: yes" || fail "trust_cos not set"
grcli qos show p0 | grep -q "port_rate: 100000" || fail "port rate not set"

# Reconfigure with WRR and DSCP trust
grcli qos set p0 wrr trust-dscp default-priority 3
grcli qos show p0 | grep -q "scheduler: wrr" || fail "scheduler not wrr"
grcli qos show p0 | grep -q "trust_dscp: yes" || fail "trust_dscp not set"
grcli qos show p0 | grep -q "default_priority: 3" || fail "default priority not 3"

# Configure second port
grcli qos set p1 dwrr port-rate 50000
grcli qos show p1 | grep -q "scheduler: dwrr" || fail "p1 scheduler not dwrr"

# Disable QoS
grcli qos set p0 off
grcli qos show p0 | grep -q "enabled: false" || fail "QoS not disabled"

# Cleanup
grcli interface del br0
