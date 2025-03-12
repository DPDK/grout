#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

grcli set affinity cpus control 0 datapath 1
grcli add interface port p0 devargs net_null0,no-rx=1 rxqs 2
grcli add interface port p1 devargs net_null1,no-rx=1 rxqs 2
grcli show affinity qmap

grcli set affinity qmap p0 rxq 0 cpu 2
grcli set affinity qmap p0 rxq 1 cpu 3
grcli set affinity qmap p1 rxq 0 cpu 2
grcli set affinity qmap p1 rxq 1 cpu 3
grcli show affinity qmap

grcli set affinity cpus datapath 4,5
grcli show affinity qmap
