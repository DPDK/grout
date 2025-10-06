#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_null0,no-rx=1
grcli interface add port p1 devargs net_null1,no-rx=1
grcli nexthop add l3 iface p0 id 42 address 1.2.3.4
grcli nexthop add l3 iface p0 id 45
grcli nexthop add l3 iface p0 id 47 address 1.2.3.7
grcli nexthop add l3 iface p1 id 1042 address f00:ba4::1
grcli nexthop add l3 iface p1 id 1047 address f00:ba4::100
grcli nexthop add l3 iface p1 id 42 address f00:ba4::666 # replace existing nexthop
grcli nexthop add l3 iface p0 address ba4:f00::1 mac ba:d0:ca:ca:00:02
grcli nexthop add l3 iface p1 address 4.3.2.1 mac ba:d0:ca:ca:00:01
grcli nexthop add blackhole id 666
grcli nexthop add reject id 123456
grcli address add 10.0.0.1/24 iface p0
grcli address add 10.1.0.1/24 iface p1
grcli route add 0.0.0.0/0 via 10.0.0.2
grcli route add 0.0.0.0/0 via 10.0.0.1 || fail "route replace should succeed"
grcli route add 4.5.21.2/27 via id 47
grcli route add 172.16.47.0/24 via id 1047
grcli address6 add 2345::1/24 iface p0
grcli address6 add 2346::1/24 iface p1
grcli route add ::/0 via 2345::2
grcli route add ::/0 via 2345::1 || fail "route replace should succeed"
grcli route add 2521:111::4/37 via id 1047
grcli route add 2521:112::/64 via id 45
grcli route add 2521:113::/64 via id 47
grcli interface set port p0 rxqs 2
grcli interface set port p1 rxqs 2
grcli interface show
grcli route show
grcli nexthop show
grcli graph show full
grcli stats show software
grcli stats show hardware
grcli nexthop del 42
grcli nexthop del 666
grcli nexthop del 123456

grcli interface del p0
grcli interface del p1

if [ "$(grcli nexthop show | wc -l)" -ne 0 ]; then fail "Nexthop list is not empty" ; fi
if [ "$(grcli route show | wc -l)" -ne 0 ]; then fail "route list is not empty" ; fi
