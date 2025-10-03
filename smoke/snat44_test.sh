#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

grcli interface add port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00
grcli interface add port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:01
grcli address add 172.16.0.1/24 iface $p0
grcli address add 10.99.0.1/24 iface $p1
grcli snat44 add interface $p0 subnet 10.99.0.0/24 replace 172.16.0.1
grcli snat44 show
grcli conntrack show
grcli conntrack config set max 1024 closed-timeout 2

for n in 0 1; do
	p=$run_id$n
	netns_add $p
	ip link set $p netns $p
	ip -n $p link set $p address ba:d0:ca:ca:00:0$n
	ip -n $p link set $p up
	ip -n $p link set lo up
done

ip -n $p0 addr add 172.16.0.2/24 dev $p0
ip -n $p1 addr add 10.99.0.99/24 dev $p1
ip -n $p1 route add default via 10.99.0.1

ip netns exec $p1 ping -i0.01 -c3 -n 172.16.0.2

ip netns exec $p0 socat -v -4 TCP4-LISTEN:1234,reuseaddr EXEC:/usr/bin/rev &
sleep 0.2
echo foobar | ip netns exec $p1 socat - TCP4:172.16.0.2:1234,shut-down > $tmp/response
[ "$(cat $tmp/response)" = raboof ] || fail "bad TCP response from server"

ip netns exec $p0 socat -v -4 UDP4-RECVFROM:1234,reuseaddr EXEC:/usr/bin/rev &
sleep 0.2
echo foobar | ip netns exec $p1 socat - UDP4:172.16.0.2:1234,shut-down > $tmp/response
[ "$(cat $tmp/response)" = raboof ] || fail "bad UDP response from server"

grcli conntrack show
grcli conntrack config show

sleep 3

grcli conntrack show
grcli conntrack config show

grcli conntrack flush
grcli conntrack show
