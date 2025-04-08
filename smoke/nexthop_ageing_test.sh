#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli set config nexthop lifetime 2 unreachable 1 ucast-probes 1 bcast-probes 1
grcli add interface port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00
grcli add interface port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:01
grcli add ip address 172.16.0.1/24 iface $p0
grcli add ip address 172.16.1.1/24 iface $p1

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:ca:00:0$n
	ip -n $p link set $p up
	ip -n $p link set lo up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

ip netns exec $p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2

grcli show ip nexthop
# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

grcli <<EOF
show ip nexthop
show ip address
EOF

# ensure that nexthops are still reachable
grcli show ip nexthop | grep -E '172\.16\.0\.2.+reachable' || fail "nexthop should be reachable"
grcli show ip nexthop | grep -E '172\.16\.1\.2.+reachable' || fail "nexthop should be reachable"
# ensure addresses were not destroyed
grcli show ip address | grep -E "^$p0[[:space:]]+172\\.16\\.0\\.1/24$" || fail "addresses were destroyed"
grcli show ip address | grep -E "^$p1[[:space:]]+172\\.16\\.1\\.1/24$" || fail "addresses were destroyed"

# force interfaces down so that linux does not reply to ARP requests anymore
ip -n $p0 link set $p0 down
ip -n $p1 link set $p1 down

# let nexthops lifetime expire and wait for ARP probes to be sent
sleep 3

# ensure that nexthops have been aged out and destroyed
! grcli show ip nexthop | grep -q '172\.16\.0\.2.*reachable' || fail "nexthop should be destroyed"
! grcli show ip nexthop | grep -q '172\.16\.1\.2.*reachable' || fail "nexthop should be destroyed"
# ensure addresses were not destroyed
grcli show ip address | grep -E "^$p0[[:space:]]+172\\.16\\.0\\.1/24$" || fail "addresses were destroyed"
grcli show ip address | grep -E "^$p1[[:space:]]+172\\.16\\.1\\.1/24$" || fail "addresses were destroyed"
