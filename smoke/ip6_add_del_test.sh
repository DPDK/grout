#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_tap0,iface=x-p0
grcli interface del p0
grcli interface add port p0 devargs net_tap0,iface=x-p0

grcli address add 2001::1/64 iface p0
grcli address show
grcli address del 2001::1/64 iface p0
grcli address show
grcli address add 2001::1/64 iface p0
grcli address show

grcli interface add vrf foo
grcli interface set port p0 vrf foo
grcli address show
grcli nexthop show internal

grcli interface add port p1 devargs net_tap1,iface=x-p1
grcli interface set port p0 domain p1
grcli interface set port p1 domain p0

grcli nexthop show internal
