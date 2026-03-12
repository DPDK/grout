#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

grout_verbose_level=1
grout_memory=4096
trace_enable=false
follow_events=hide
. $(dirname $0)/_init.sh

# Simulate a full IPv6 BGP view: ~200K prefixes.
count=200000

# Create a dummy port to trigger default VRF auto-creation.
grcli interface add port p0 devargs net_null0,no-rx=1

grcli route config set vrf main rib6-routes $((count + 10))

fib_inject -6 -n $count

grcli route config show
