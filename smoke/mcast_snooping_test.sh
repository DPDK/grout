#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

# Create bridge and ports
grcli interface add bridge br0
port_add p0 domain br0
port_add p1 domain br0

# Enable multicast snooping with IGMP
grcli mcast-snooping set br0 igmp
grcli mcast-snooping show br0 | grep -q "igmp: enabled" || fail "IGMP not enabled"
grcli mcast-snooping show br0 | grep -q "mld: disabled" || fail "MLD should be disabled"
grcli mcast-snooping show br0 | grep -q "query_interval: 125" || fail "default query interval wrong"
grcli mcast-snooping show br0 | grep -q "aging_time: 260" || fail "default aging time wrong"

# Reconfigure with MLD and querier
grcli mcast-snooping set br0 igmp mld querier query-interval 60 aging-time 120
grcli mcast-snooping show br0 | grep -q "igmp: enabled" || fail "IGMP not enabled after reconfig"
grcli mcast-snooping show br0 | grep -q "mld: enabled" || fail "MLD not enabled"
grcli mcast-snooping show br0 | grep -q "querier: enabled" || fail "querier not enabled"
grcli mcast-snooping show br0 | grep -q "query_interval: 60" || fail "query interval not updated"
grcli mcast-snooping show br0 | grep -q "aging_time: 120" || fail "aging time not updated"

# MDB should be empty initially
grcli mcast-snooping show br0 | grep -q "mdb_entries: 0" || fail "MDB should be empty"

# Cleanup
grcli interface del br0
