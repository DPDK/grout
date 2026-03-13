#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

# Simulate a full IPv4 BGP view: ~1M prefixes.
count=1000000

# Create a dummy port to trigger default VRF auto-creation.
grcli interface add port p0 devargs net_null0,no-rx=1

grcli interface set vrf main rib4-routes $((count + 10))

fib_inject -4 -n $count

grcli route config show
