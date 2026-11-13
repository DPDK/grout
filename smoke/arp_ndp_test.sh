#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

# grout replies to ARP requests and neighbor solicitations following the strong
# host model: an address is only answered on the interface that owns it, unless
# it is explicitly exposed on other interfaces. When an interface MAC changes,
# the new MAC is used in subsequent replies. Gratuitous ARP announcements are
# learned into the neighbor table when the sender is already known, or when
# neighbor snooping is enabled on the receiving interface.

reply() {
	local ns="$1" mac="$2"
	shift 2
	ip netns exec "$ns" "$@" | tee $tmp/reply || fail "$* got no reply"
	grep -iq "$mac" $tmp/reply || fail "$* reply did not contain mac $mac"
}

no_reply() {
	local ns="$1"
	shift
	if ip netns exec "$ns" "$@"; then
		fail "$* unexpectedly got a reply"
	fi
}

mac0=ba:d0:ca:ca:00:01
mac1=ba:d0:ca:ca:00:02
port_add p0 mac $mac0 vrf main
port_add p1 mac $mac1 vrf main

grcli address add 192.168.0.1/24 iface p0
grcli address add fd00:1::1/64 iface p0
grcli address add 192.168.1.1/24 iface p1
grcli address add fd00:2::1/64 iface p1

# The loopback address is only exposed on p0.
grcli address add 10.99.0.1/32 iface main
grcli address add fd00:99::1/128 iface main
grcli address expose 10.99.0.1/32 iface p0
grcli address expose fd00:99::1/128 iface p0

# This one is exposed on both p0 and p1.
grcli address add 10.99.0.2/32 iface main
grcli address add fd00:99::2/128 iface main
grcli address expose 10.99.0.2/32 iface p0
grcli address expose 10.99.0.2/32 iface p1
grcli address expose fd00:99::2/128 iface p0
grcli address expose fd00:99::2/128 iface p1

# The exposure targets are reported when listing addresses.
grcli address show | grep -E "10.99.0.1/32\s+p0$" || fail "10.99.0.1 not exposed on p0"
grcli address show | grep -E "10.99.0.2/32\s+p0,p1$" || fail "10.99.0.2 not exposed on p0,p1"

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 192.168.0.2/24 dev x-p0
ip -n n0 -6 addr add fd00:1::2/64 dev x-p0

netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 192.168.1.2/24 dev x-p1
ip -n n1 -6 addr add fd00:2::2/64 dev x-p1

# An interface answers for its own addresses.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0

# The loopback exposed on p0 is answered there.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::1 x-p0

# The loopback exposed on both ports is answered on p0 and p1.
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.2
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::2 x-p0
reply n1 $mac1 arping -c1 -I x-p1 -s 192.168.1.2 10.99.0.2
reply n1 $mac1 ndisc6 -1 -r1 -s fd00:2::2 fd00:99::2 x-p1

# Strong host: p1 does not answer for an address owned by p0.
no_reply n1 arping -c1 -w1 -I x-p1 -s 192.168.1.2 192.168.0.1
no_reply n1 ndisc6 -1 -r1 -w1000 -s fd00:2::2 fd00:1::1 x-p1

# The loopback is not exposed on p1, so p1 does not answer for it.
no_reply n1 arping -c1 -w1 -I x-p1 -s 192.168.1.2 10.99.0.1
no_reply n1 ndisc6 -1 -r1 -w1000 -s fd00:2::2 fd00:99::1 x-p1

mark_events

# Changing the MAC in grout is reflected in ARP/NDP replies.
mac0=02:0f:00:0b:a4:01
grcli interface set port p0 mac $mac0

wait_event "nh update: type=L3 iface=p0 .*addr=192.168.0.1/24 state=reachable mac=$mac0"
wait_event "nh update: type=L3 iface=p0 .*addr=fd00:1::1/64 state=reachable mac=$mac0"

# The MAC change is mirrored on the linux tap interface. Revert back to the
# stable MAC set at creation by port_add.
ip -n n0 link set x-p0 address $(stable_mac p0)

reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0
reply n0 $mac0 arping -c1 -I x-p0 -s 192.168.0.2 10.99.0.1
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:1::2 fd00:99::1 x-p0

# Gratuitous ARP announcements (ARP requests where sip == tip) are treated
# like unsolicited ARP replies: the neighbor table is updated only if an entry
# already exists for the sender, or if neighbor snooping is enabled on the
# receiving interface (similar to Linux's net.ipv4.arp_accept sysctl). A
# gratuitous ARP is learned but never answered.

# p1 already knows 192.168.1.2 (learned from the reply above): a gratuitous
# announcement with a new MAC for it is accepted even without neigh_snoop.
garp_mac=ba:d0:ca:ca:00:03
ip -n n1 link set x-p1 address $garp_mac
mark_events
ip netns exec n1 arping -U -c3 -w3 -I x-p1 192.168.1.2 &
garp_pid=$!
# grout must not answer a gratuitous ARP: no reply claiming 192.168.1.2
# (opcode=2, sender protocol address 192.168.1.2 == 0xc0a80102).
ip netns exec n1 timeout 3 \
	tcpdump -c1 -tlpnn -i x-p1 'arp[6:2] = 2 and arp[14:4] = 0xc0a80102' 2>&1 &&
	fail "grout replied to a gratuitous ARP for 192.168.1.2"
wait $garp_pid
wait_event "nh update: type=L3 .*addr=192.168.1.2 state=reachable mac=$garp_mac"
ip -n n1 link set x-p1 address $(stable_mac p1)

# p1 has no entry for 192.168.1.50 and neigh_snoop is off: the announcement is
# ignored and no nexthop is created for it. arping -U uses the target as the
# source, so the address must exist on the interface.
ip -n n1 addr add 192.168.1.50/24 dev x-p1
ip netns exec n1 arping -U -c1 -w1 -I x-p1 192.168.1.50
grcli nexthop show | grep -q 192.168.1.50 && fail "gratuitous ARP learned without neigh_snoop"

# Enabling neighbor snooping on p1 makes the same announcement learned.
grcli interface set port p1 neigh_snoop on
mark_events
ip netns exec n1 arping -U -c1 -w1 -I x-p1 192.168.1.50
wait_event "nh new: type=L3 .*iface=p1 .*origin=learn family=ipv4 addr=192.168.1.50 state=reachable mac=$(stable_mac p1)"

# Off-prefix NDP traffic is rejected without snooping and cached without a
# /128 route when snooping is enabled.
ip -n n1 -6 addr add fd00:dead::2/64 dev x-p1
grcli interface set port p1 neigh_snoop off
no_reply n1 ndisc6 -1 -r1 -w1000 -s fd00:dead::2 fd00:2::1 x-p1
grcli nexthop show | grep -q fd00:dead::2 && fail "off-prefix NDP learned without neigh_snoop"
grcli interface set port p1 neigh_snoop on
mark_events
reply n1 $mac1 ndisc6 -1 -r1 -s fd00:dead::2 fd00:2::1 x-p1
wait_event "nh new: type=L3 .*iface=p1 .*origin=learn family=ipv6 addr=fd00:dead::2 state=reachable mac=$(stable_mac p1)"
if grcli route get fd00:dead::2; then fail "snoop-only neighbor installed a /128 route"; fi

# Without neighbor snooping, off-prefix ARP requests for local addresses
# still get a reply, but their senders are not learned.
ip -n n1 addr add 192.168.0.50/24 dev x-p1
grcli interface set port p1 neigh_snoop off
reply n1 $mac1 arping -c1 -w1 -I x-p1 -s 192.168.0.50 192.168.1.1
ip netns exec n1 arping -A -c1 -I x-p1 192.168.0.50
grcli nexthop show | grep -q 192.168.0.50 && fail "off-prefix ARP learned without neigh_snoop"

# Snoop-only neighbors are cached but must not install an internal /32 route.
grcli interface set port p1 neigh_snoop on
mark_events
ip netns exec n1 arping -U -c1 -w1 -I x-p1 192.168.0.50
wait_event "nh new: type=L3 .*iface=p1 .*origin=learn family=ipv4 addr=192.168.0.50 state=reachable mac=$(stable_mac p1)"
grcli -j route get 192.168.0.50 | jq -e '.nexthop.iface == "p0"' || fail "snoop-only neighbor installed a /32 route"

# The same behavior applies when the SVI has no IPv4 address at all.
ip -n n1 addr add 192.168.0.51/24 dev x-p1
grcli address del 192.168.1.1/24 iface p1
mark_events
ip netns exec n1 arping -U -c1 -w1 -I x-p1 192.168.0.51
wait_event "nh new: type=L3 .*iface=p1 .*origin=learn family=ipv4 addr=192.168.0.51 state=reachable mac=$(stable_mac p1)"
grcli -j route get 192.168.0.51 | jq -e '.nexthop.iface == "p0"' || fail "snooped neighbor on unnumbered SVI installed a /32 route"

# A connected neighbor takes over the snooped entry and installs a host route.
ip -n n0 addr add 192.168.0.50/24 dev x-p0
reply n0 $mac0 arping -c1 -w1 -I x-p0 -s 192.168.0.50 192.168.0.1
grcli -j route get 192.168.0.50 | jq -e '.nexthop.addr == "192.168.0.50" and .nexthop.iface == "p0"' || fail "snooped IPv4 neighbor was not promoted"
grcli -j nexthop show type l3 | jq -e '.[] | select(.addr == "192.168.0.50" and .iface == "p0")' || fail "snooped IPv4 neighbor is on the wrong interface"

grcli address add fd00:dead::1/64 iface p0
ip -n n0 -6 addr add fd00:dead::2/64 dev x-p0
reply n0 $mac0 ndisc6 -1 -r1 -s fd00:dead::2 fd00:dead::1 x-p0
grcli -j route get fd00:dead::2 | jq -e '.nexthop.addr == "fd00:dead::2" and .nexthop.iface == "p0"' || fail "snooped IPv6 neighbor was not promoted"
grcli -j nexthop show type l3 | jq -e '.[] | select(.addr == "fd00:dead::2" and .iface == "p0")' || fail "snooped IPv6 neighbor is on the wrong interface"

# A gratuitous ARP must only touch a neighbor learned on the interface it was
# received on. 192.168.0.2 is a neighbor on p0; announcing it on p1 (even with
# neigh_snoop on) must not steal it or rewrite its MAC.
ip -n n1 addr add 192.168.0.2/24 dev x-p1
ip netns exec n1 arping -U -c1 -w1 -I x-p1 192.168.0.2
sleep 1
nh=$(grcli -j nexthop show type l3 | jq -r '.[] | select(.addr == "192.168.0.2")')
[ "$(echo "$nh" | jq -r .iface)" = p0 ] || fail "192.168.0.2 moved away from p0"
[ "$(echo "$nh" | jq -r .mac)" = "$(stable_mac p0)" ] || fail "192.168.0.2 MAC was hijacked from p1"
