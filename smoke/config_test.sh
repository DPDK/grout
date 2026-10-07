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
grcli graph config set vector-max 256 rx-burst-max 64
grcli -j graph config show | jq -e 'select(.vector_max == 256 and .rx_burst_max == 64)'
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

# Test control-plane log rate limiting and error accounting.
grcli -j log rate show | jq -e 'select(.rate == 10)' || fail "default log rate should be 10"
grcli log rate set 42
grcli -j log rate show | jq -e 'select(.rate == 42)' || fail "log rate should be 42"
grcli log rate set 0
grcli -j log rate show | jq -e 'select(.rate == 0)' || fail "log rate should be 0 (unlimited)"
# Use a limit of 1 message/second so that any flood is deterministically capped.
grcli log rate set 1
grcli -j log rate show | jq -e 'select(.rate == 1)' || fail "log rate should be 1"

# The control-plane counters are reported through "stats show software" and are
# hidden while zero unless "zero" is passed.
grcli -j stats show software zero | jq -e '.[] | select(.node == "ctlplane.rx_bad_ether_type")' \
	|| fail "ctlplane control-plane stat should be reported"
grcli -j stats show software | jq -e '.[] | select(.node == "ctlplane.rx_bad_ether_type")' \
	&& fail "zero control-plane stat should be hidden without zero"

# Drive a floodable control-plane path on purpose and check that every
# occurrence is counted while the log output stays bounded. A unicast frame
# addressed to the port MAC with a non-IP ethertype injected into the control
# plane tap hits CP_ERR(rx_bad_ether_type) in iface_cp_poll.
cp_mac=$(grcli -j interface show name p2 | jq -r .mac)
# grout reads the control plane tap once the port link is up; force it up and
# wait for LOWER_UP before injecting, otherwise the kernel drops the frames.
ip link set p2 up
SECONDS=0
while ! ip -o link show p2 | grep -qw LOWER_UP; do
	[ "$SECONDS" -gt 5 ] && fail "control plane tap p2 was not up after 5 seconds"
	sleep 0.2
done

# Inject raw unicast frames with a python AF_PACKET socket (no scapy).
cp_send() {
	python3 - p2 "$cp_mac" "$1" <<'EOF'
import socket, sys
dev, mac, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
dst = bytes(int(b, 16) for b in mac.split(":"))
frame = dst + b"\x02\x00\x00\x00\x00\x99" + b"\x08\x06" + b"\x00" * 46
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((dev, 0))
for _ in range(count):
    s.send(frame)
EOF
}

# First burst: with a 1/s limit, a single line is logged and the rest suppressed.
cp_send 5
# Every frame is accounted for even though most are not logged.
SECONDS=0
while [ "$(grcli -j stats show software zero |
	jq '.[] | select(.node == "ctlplane.rx_bad_ether_type") | .packets')" -lt 5 ]; do
	[ "$SECONDS" -gt 5 ] && fail "control-plane errors were not all accounted"
	sleep 0.2
done
logged=$(grep -c "unexpected ether_type" $tmp/grout.log || true)
[ "$logged" -lt 5 ] || fail "log was not rate limited ($logged lines for 5 errors)"

# Second burst in the next window: the first emitted line reports the number of
# messages suppressed since the previous one.
sleep 1.2
cp_send 5
SECONDS=0
while ! grep -qF "messages rate limited" $tmp/grout.log; do
	[ "$SECONDS" -gt 10 ] && fail "resume message with suppressed count never appeared"
	sleep 0.2
done

accounted=$(grcli -j stats show software zero |
	jq '.[] | select(.node == "ctlplane.rx_bad_ether_type") | .packets')
[ "$accounted" = 10 ] || fail "all 10 errors should be accounted, got $accounted"

# "stats reset" clears the control-plane counters.
grcli stats reset
accounted=$(grcli -j stats show software zero |
	jq '.[] | select(.node == "ctlplane.rx_bad_ether_type") | .packets')
[ "$accounted" = 0 ] || fail "control-plane counter should be 0 after reset, got $accounted"

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
