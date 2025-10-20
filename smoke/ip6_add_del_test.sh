#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

p0=${run_id}0

grcli interface add port $p0 devargs net_tap0,iface=$p0
grcli interface del $p0
grcli interface add port $p0 devargs net_tap0,iface=$p0

grcli address add 2001::1/64 iface $p0
grcli address show
grcli address del 2001::1/64 iface $p0
grcli address show
grcli address add 2001::1/64 iface $p0
grcli address show
