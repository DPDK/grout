#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli add interface port p0 devargs net_null0,no-rx=1
grcli add interface port p1 devargs net_null1,no-rx=1
grcli add nexthop id 42 address 1.2.3.4 iface p0
grcli add nexthop id 45 iface p0
grcli add nexthop id 47 address 1.2.3.7 iface p0
grcli add nexthop id 1042 address f00:ba4::1 iface p1
grcli add nexthop id 1047 address f00:ba4::100 iface p1
grcli add nexthop id 42 address f00:ba4::666 iface p1 # replace existing nexthop
grcli add nexthop address ba4:f00::1 iface p0 mac ba:d0:ca:ca:00:02
grcli add nexthop address 4.3.2.1 iface p1 mac ba:d0:ca:ca:00:01
grcli add ip address 10.0.0.1/24 iface p0
grcli add ip address 10.1.0.1/24 iface p1
grcli add ip route 0.0.0.0/0 via 10.0.0.2
grcli add ip route 0.0.0.0/0 via 10.0.0.1 || fail "route replace should succeed"
grcli add ip route 4.5.21.2/27 via id 47
grcli add ip route 172.16.47.0/24 via id 1047
grcli add ip6 address 2345::1/24 iface p0
grcli add ip6 address 2346::1/24 iface p1
grcli add ip6 route ::/0 via 2345::2
grcli add ip6 route ::/0 via 2345::1 || fail "route6 replace should succeed"
grcli add ip6 route 2521:111::4/37 via id 1047
grcli add ip6 route 2521:112::/64 via id 45
grcli add ip6 route 2521:113::/64 via id 47
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

grcli del interface p0
grcli del interface p1

if [ "$(grcli show nexthop | wc -l)" -ne 0 ]; then fail "Nexthop list is not empty" ; fi
if [ "$(grcli show ip route | wc -l)" -ne 0 ]; then fail "RIB4 is not empty" ; fi
if [ "$(grcli show ip6 route | wc -l)" -ne 0 ]; then fail "RIB6 is not empty" ; fi
