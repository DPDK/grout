#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

# configure a bunch of stuff
grcli -xe <<EOF
interface add bond bond0 mode lacp
interface add port p0 devargs net_null0,no-rx=1 rxqs 2 master bond0
interface add port p1 devargs net_null1,no-rx=1 rxqs 2 master bond0
interface add vlan v42 parent bond0 vlan_id 42 vrf 1
interface add vlan v43 parent bond0 vlan_id 43 vrf 2
nexthop add l3 iface v42 id 42 address 1.2.3.4
nexthop add l3 iface v42 id 45
nexthop add l3 iface v42 id 47 address 1.2.3.7
nexthop add l3 iface v43 id 1042 address f00:ba4::1
nexthop add l3 iface v43 id 1047 address f00:ba4::100
nexthop add l3 iface v42 address ba4:f00::1 mac ba:d0:ca:ca:00:02
nexthop add l3 iface v43 address 4.3.2.1 mac ba:d0:ca:ca:00:01
nexthop add blackhole id 666 vrf 1
nexthop add reject id 123456 vrf 2
address add 10.0.0.1/24 iface v42
address add 10.1.0.1/24 iface v43
route add 0.0.0.0/0 via 10.0.0.2 vrf 1
route add 4.5.21.2/27 via id 47 vrf 1
route add 172.16.47.0/24 via id 1047 vrf 2
interface add ipip tun0 local 10.0.0.1 remote 10.0.0.111 vrf 1
address add 2345::1/24 iface v42
address add 2346::1/24 iface v43
route add ::/0 via 2345::2 vrf 1
route add 2521:111::4/37 via id 1047 vrf 1
route add 2521:112::/64 via id 45 vrf 2
route add 2521:113::/64 via id 47 vrf 1
EOF

# dump all metrics
curl --fail http://localhost:9111/metrics
