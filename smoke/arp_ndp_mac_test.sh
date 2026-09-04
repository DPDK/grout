#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

mac=ba:d0:ca:ca:00:01

check_arp_ndp() {
	ip netns exec n0 "$@" | tee $tmp/arp || fail "$* failed"
	grep -iq "$mac" $tmp/arp || fail "grout reply didn't have mac $mac"
}

port_add p0 mac $mac vrf main

grcli address add 192.168.110.1/32 iface main
grcli address add fd00:110::1/128 iface main

grcli address add 192.168.0.1/24 iface p0
grcli address add fd00:1::1/64 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 192.168.0.2/24 dev x-p0
ip -n n0 -6 addr add fd00:1::2/64 dev x-p0
ip -n n0 route add default via 192.168.0.1 dev x-p0
ip -n n0 -6 route add default via fd00:1::1 dev x-p0

check_arp_ndp arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
check_arp_ndp arping -c1 -I x-p0 -s 192.168.0.2 192.168.110.1
check_arp_ndp ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0
check_arp_ndp ndisc6 -1 -r1 -s fd00:1::2 fd00:110::1 x-p0

mark_events

mac=02:0f:00:0b:a4:01
grcli interface set port p0 mac $mac

wait_event "nh update: type=L3 iface=p0 .*addr=192.168.0.1/24 state=reachable mac=$mac"
wait_event "nh update: type=L3 iface=p0 .*addr=fd00:1::1/64 state=reachable mac=$mac"

# Changing the mac in grout is mirrored on the linux tap interface. Revert back
# to the stable mac set at creation by port_add.
ip -n n0 link set x-p0 address $(stable_mac p0)

check_arp_ndp arping -c1 -I x-p0 -s 192.168.0.2 192.168.0.1
check_arp_ndp arping -c1 -I x-p0 -s 192.168.0.2 192.168.110.1
check_arp_ndp ndisc6 -1 -r1 -s fd00:1::2 fd00:1::1 x-p0
check_arp_ndp ndisc6 -1 -r1 -s fd00:1::2 fd00:110::1 x-p0
