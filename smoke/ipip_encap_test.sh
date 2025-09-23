#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1
iptun=${run_id}tun1

grcli interface add port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:01
grcli interface add port $p1 devargs net_tap1,iface=$p1 mac f0:0d:ac:dc:00:02
grcli address add 10.99.0.1/24 iface $p0
grcli address add 172.16.1.1/24 iface $p1
grcli interface add ipip $iptun local 172.16.1.1 remote 172.16.1.2
grcli address add 10.98.0.1/24 iface $iptun

netns_add $p0
ip link set $p0 netns $p0
ip -n $p0 link set $p0 address ba:d0:ca:ca:00:00
ip -n $p0 link set $p0 up
ip -n $p0 addr add 10.99.0.2/24 dev $p0
ip -n $p0 route add default via 10.99.0.1
ip -n $p0 addr show

netns_add $p1
ip link set $p1 netns $p1
ip -n $p1 link set $p1 address ba:d0:ca:ca:00:01
ip -n $p1 link set $p1 up
ip -n $p1 addr add 172.16.1.2/24 dev $p1
ip -n $p1 tunnel add $iptun mode ipip local 172.16.1.2 remote 172.16.1.1
ip -n $p1 link set $iptun up
ip -n $p1 addr add 10.98.0.2/24 dev $iptun
ip -n $p1 route add default via 10.98.0.1
ip -n $p1 addr show

ip netns exec $p0 ping -i0.01 -c3 -n 10.98.0.2
ip netns exec $p1 ping -i0.01 -c3 -n 10.99.0.2
