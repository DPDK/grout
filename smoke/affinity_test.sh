#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

# Start with a single datapath CPU.
grcli affinity cpus set control 0 datapath 1
grcli interface add port p0 devargs net_null0,no-rx=1 rxqs 2
grcli interface add port p1 devargs net_null1,no-rx=1 rxqs 2
grcli affinity qmap show

# Ensure that trying to manually move rxqs to CPUs outside of the reserved
# datapath affinity mask returns an error.
grcli affinity qmap set p0 rxq 0 cpu 666 && fail "qmap to CPU 666 should fail"
grcli affinity qmap set p0 rxq 0 cpu 2 && fail "qmap to CPU 2 should fail"

grcli affinity cpus set datapath 1,2,3
grcli affinity qmap show

grcli affinity qmap set p0 rxq 0 cpu 1
grcli affinity qmap set p0 rxq 1 cpu 1
grcli affinity qmap set p1 rxq 0 cpu 2
grcli affinity qmap set p1 rxq 1 cpu 2
grcli affinity qmap show

grcli affinity cpus set datapath 2,3
grcli affinity qmap show

# ensure deleting and recreating ports does not cause a crash
grcli interface del p0
grcli interface add port p0 devargs net_null0,no-rx=1 rxqs 2
grcli interface del p1
grcli interface add port p1 devargs net_null1,no-rx=1 rxqs 3
grcli interface del p0
grcli stats show
grcli interface del p1
grcli stats show
