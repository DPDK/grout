#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1
iptun=${run_id}tun1

br-cli add interface port $p0 devargs net_tap0,iface=$p0
br-cli add interface port $p1 devargs net_tap1,iface=$p1
br-cli add ip address 10.99.0.1/24 iface $p0
br-cli add ip address 172.16.1.1/24 iface $p1
br-cli add interface ipip $iptun local 172.16.1.1 remote 172.16.1.2
br-cli add ip address 10.98.0.1/24 iface $iptun

ip netns add $p0
echo ip netns del $p0 >> $tmp/cleanup
ip link set $p0 netns $p0
ip -n $p0 link set $p0 up
ip -n $p0 addr add 10.99.0.2/24 dev $p0
ip -n $p0 route add default via 10.99.0.1

ip netns add $p1
echo ip netns del $p1 >> $tmp/cleanup
ip link set $p1 netns $p1
ip -n $p1 link set $p1 up
ip -n $p1 addr add 172.16.1.2/24 dev $p1
ip -n $p1 tunnel add $iptun mode ipip local 172.16.1.2 remote 172.16.1.1
ip -n $p1 link set $iptun up
ip -n $p1 addr add 10.98.0.2/24 dev $iptun
ip -n $p1 route add default via 10.98.0.1

ip netns exec $p0 ping -i0.01 -c3 10.98.0.2
ip netns exec $p1 ping -i0.01 -c3 10.99.0.2
