#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Christophe Fontaine

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli add interface port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00
grcli add interface port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:01
grcli add ip address 172.16.2.1/24 iface $p0
grcli add ip address 172.16.0.1/24 iface $p0
grcli add ip address 172.16.1.1/24 iface $p1

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:ca:00:0$n
	ip -n $p link set $p up
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
	ip -n $p addr show
done

set -m

grcli ping 172.16.0.2 count 10 delay 100 &
grcli ping 172.16.1.2 count 3 delay 10

fg

# Expect this test to fail
grcli ping 1.1.1.1 count 1 && fail "ping to unknown route succeeded"
grcli ping 172.16.1.3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute 172.16.0.2
