#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli add interface port p0 devargs net_null0,no-rx=1
grcli add interface port p1 devargs net_null1,no-rx=1
grcli add nexthop 1.2.3.4 iface p0 id 42
grcli add nexthop 1.2.3.7 iface p0 id 47
grcli add nexthop f00:ba4::1 iface p1 id 1042
grcli add nexthop f00:ba4::100 iface p1 id 1047
grcli add nexthop f00:ba4::666 iface p1 id 42 # replace existing nexthop
grcli add nexthop ba4:f00::1 iface p0 mac ba:d0:ca:ca:00:02
grcli add nexthop 4.3.2.1 iface p1 mac ba:d0:ca:ca:00:01
grcli add ip address 10.0.0.1/24 iface p0
grcli add ip address 10.1.0.1/24 iface p1
grcli add ip route 0.0.0.0/0 via 10.0.0.2
grcli add ip route 4.5.21.2/27 via id 47
grcli add ip6 address 2345::1/24 iface p0
grcli add ip6 address 2346::1/24 iface p1
grcli add ip6 route ::/0 via 2345::2
grcli add ip6 route 2521:111::4/37 via id 1047
grcli set interface port p0 rxqs 2
grcli set interface port p1 rxqs 2
grcli show interface
grcli show ip route
grcli show ip6 route
grcli show nexthop
grcli show graph full
grcli show stats software
grcli show stats hardware
grcli del nexthop id 42
grcli del nexthop ba4:f00::1
