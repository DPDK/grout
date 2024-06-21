#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli add interface port p0 devargs net_null0
grcli add interface port p1 devargs net_null1
grcli add ip address 10.0.0.1/24 iface p0
grcli add ip address 10.1.0.1/24 iface p1
grcli add ip route 0.0.0.0/0 via 10.0.0.2
grcli show interface all
grcli show ip route
grcli show ip nexthop
grcli show graph dot
grcli show stats software
grcli show stats hardware
