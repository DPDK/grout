#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

# Start with a single datapath CPU.
grcli set affinity cpus control 0 datapath 1
grcli add interface port p0 devargs net_null0,no-rx=1 rxqs 2
grcli add interface port p1 devargs net_null1,no-rx=1 rxqs 2
grcli show affinity qmap

# Ensure that trying to manually move rxqs to CPUs outside of the reserved
# datapath affinity mask returns an error.
grcli set affinity qmap p0 rxq 0 cpu 666 && fail "qmap to CPU 666 should fail"
grcli set affinity qmap p0 rxq 0 cpu 2 && fail "qmap to CPU 2 should fail"

grcli set affinity cpus datapath 1,2,3
grcli show affinity qmap

grcli set affinity qmap p0 rxq 0 cpu 1
grcli set affinity qmap p0 rxq 1 cpu 1
grcli set affinity qmap p1 rxq 0 cpu 2
grcli set affinity qmap p1 rxq 1 cpu 2
grcli show affinity qmap

grcli set affinity cpus datapath 2,3
grcli show affinity qmap
