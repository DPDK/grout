#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

grcli interface add bond bond0 mode lacp description "lacp trunk"
grcli interface add port p0 devargs net_null0,no-rx=1 domain bond0
grcli interface add port p1 devargs net_null1,no-rx=1 domain bond0 description "uplink port"
grcli interface add vlan v42 parent bond0 vlan_id 42
grcli interface add vlan v43 parent bond0 vlan_id 43
grcli nexthop add l3 iface p0 id 42 address 1.2.3.4
grcli nexthop add l3 iface p0 id 45
grcli nexthop add l3 iface p0 id 47 address 1.2.3.7
grcli nexthop add l3 iface p0 id 42 address 1.2.3.7 && fail "duplicate address should fail"
grcli -j nexthop show type l3 | jq -e '.[] | select(.id == 42 and .addr == "1.2.3.4")' || fail "nexthop 42 should still have 1.2.3.4"
grcli -j nexthop show type l3 | jq -e '.[] | select(.id == 47 and .addr == "1.2.3.7")' || fail "nexthop 47 should still have 1.2.3.7"
grcli nexthop add l3 iface p1 id 1042 address f00:ba4::1
grcli nexthop add l3 iface p1 id 1047 address f00:ba4::100
grcli nexthop add l3 iface p1 id 42 address f00:ba4::666 # replace existing nexthop
grcli nexthop add l3 iface p0 address ba4:f00::1 mac ba:d0:ca:ca:00:02
grcli nexthop add l3 iface p1 address 4.3.2.1 mac ba:d0:ca:ca:00:01
grcli nexthop add blackhole id 666
grcli nexthop add reject id 123456
grcli nexthop add group id 333 member 42 weight 102
grcli nexthop add group id 333 member 45 member 47
grcli nexthop add group id 334 member 42 weight 10000 member 45 weight 1
grcli nexthop add group id 334
grcli interface add port p2 devargs net_null2,no-rx=1
grcli interface add port p3 devargs net_null3,no-rx=1
grcli address add 10.0.0.1/24 iface p2
grcli address add 10.1.0.1/24 iface p3
grcli route add 0.0.0.0/0 via 10.0.0.2
grcli route add 0.0.0.0/0 via 10.0.0.1 || fail "route replace should succeed"
grcli route add 4.5.21.2/27 via id 47
grcli route add 172.16.47.0/24 via id 1047
grcli address add 2345::1/24 iface p2
grcli address add 2346::1/24 iface p3
grcli route add ::/0 via 2345::2
grcli route add ::/0 via 2345::1 || fail "route replace should succeed"
grcli route add 2521:111::4/37 via id 1047
grcli route add 2521:112::/64 via id 45
grcli route add 2521:113::/64 via id 47
grcli interface set port p0 rxqs 2
grcli interface set port p1 rxqs 2
grcli interface set port p2 description "peering link"
grcli interface set port p0 name main && fail "using a reserved name should fail"
grcli interface set port p0 name thisisasuperlonginterfacename && fail "long interface names should be rejected"
grcli interface set port p0 name . && fail "using an invalid name should fail"
grcli interface set port p0 name .. && fail "using an invalid name should fail"
grcli interface set port p0 name "ok ok" && fail "using an invalid name should fail"
grcli interface set port p0 name foo/bar && fail "using an invalid name should fail"

grcli -xe <<EOF
interface show
interface show name bond0
interface show name p2
route show
nexthop show
graph show full
stats show software
stats show hardware
EOF

grcli -xej <<EOF
interface show
interface show name bond0
address show
route show
route config show
route get 10.0.0.1
route get 2345::1
nexthop show
stats show software
stats show hardware
EOF

grcli -j interface show | jq -e '.[] | select(.info | contains("uplink port"))' || fail "p1 description not in list"
grcli -j interface show name p2 | jq -e 'select(.description == "peering link")' || fail "p2 description not set"
grcli -j interface show name bond0 | jq -e 'select(.description == "lacp trunk")' || fail "bond0 description not set"

# Test nexthop structured JSON output
grcli -j nexthop show type l3 | jq -e '.[0] | has("family", "addr")' || fail "L3 nexthop should have structured family and addr fields"
grcli -j nexthop show id 42 | jq -e 'has("type", "id", "family", "addr")' || fail "nexthop show by ID should have structured fields"
grcli -j route get 10.0.0.1 | jq -e '.nexthop | has("type", "family")' || fail "route get nexthop should be a structured object"

# Test address del cleans up connected routes
grcli address del 10.1.0.1/24 iface p3
grcli -j route show | jq -e '.[] | select(.destination == "10.1.0.0/24")' && fail "connected route should be removed after address del"
grcli address del 2346::1/24 iface p3
grcli -j route show | jq -e '.[] | select(.destination == "2346::/24")' && fail "connected route should be removed after address del"
# Test address flush with family filter
grcli address add 10.2.0.1/24 iface p3
grcli address add 2347::1/24 iface p3
grcli address show iface p3
grcli address flush ipv4 iface p3
grcli address show iface p3
grcli -j address show iface p3 | jq -e '.[] | select(.address == "10.2.0.1/24")' && fail "p3 should have no ipv4 after ipv4 flush"
grcli -j address show iface p3 | jq -e '.[] | select(.address == "2347::1/24")' || fail "p3 should still have ipv6 after ipv4 flush"
grcli address flush ipv6 iface p3
grcli -j address show iface p3 | jq -e '.[] | select(.address == "2347::1/24")' && fail "p3 should have no user ipv6 after ipv6 flush"
grcli -j address show iface p3 | jq -e '.[] | select(.address | startswith("fe80:"))' || fail "p3 should still have link-local after ipv6 flush"
# Test flush all families (default)
grcli address add 10.3.0.1/24 iface p3
grcli address add 2348::1/24 iface p3
grcli address flush iface p3
grcli -j address show iface p3 | jq -e '.[] | select(.address == "10.3.0.1/24")' && fail "p3 should have no IPv4 after flush"
grcli -j address show iface p3 | jq -e '.[] | select(.address == "2348::1/24")' && fail "p3 should have no user IPv6 after flush"
grcli -j address show iface p3 | jq -e '.[] | select(.address | startswith("fe80:"))' || fail "p3 should still have link-local after flush"

# Test SRv6 tunsrc set/clear (internal nexthop with no VRF)
grcli tunsrc set fd00::1 || fail "tunsrc set should succeed"
grcli tunsrc show | grep -qF 'fd00::1' || fail "tunsrc addr should be fd00::1"
grcli tunsrc clear || fail "tunsrc clear should succeed"
grcli tunsrc show | grep -qF '::' || fail "tunsrc addr should be unspec after clear"

grcli nexthop del 42
grcli nexthop del 666
grcli nexthop del 123456
grcli nexthop del 333
grcli nexthop del 334

grcli interface del v42
grcli interface del v43
grcli interface del bond0
grcli interface del p0
grcli interface del p1
grcli interface del p2
grcli interface del p3

if [ "$(grcli -j nexthop show | jq length)" -ne 0 ]; then fail "Nexthop list is not empty" ; fi
if [ "$(grcli -j route show | jq length)" -ne 0 ]; then fail "route list is not empty" ; fi
