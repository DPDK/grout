#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Fabien Dupont

. $(dirname $0)/_init.sh

grcli interface add bridge br0
port_add p0 domain br0

grcli ipsg set br0 verify-source log
grcli ipsg show br0 | grep -q "enabled: true" || fail "IPSG not enabled"
grcli ipsg show br0 | grep -q "verify_source: yes" || fail "verify not set"
grcli ipsg show br0 | grep -q "log_violations: yes" || fail "log not set"

grcli ipsg set br0 off
grcli ipsg show br0 | grep -q "enabled: false" || fail "not disabled"

grcli interface del br0
