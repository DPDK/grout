#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 10.99.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli interface add ipip tun1 local 172.16.1.1 remote 172.16.1.2
grcli address add 10.98.0.1/24 iface tun1

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 10.99.0.2/24 dev x-p0
ip -n n0 route add default via 10.99.0.1

netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 172.16.1.2/24 dev x-p1
ip -n n1 tunnel add tun1 mode ipip local 172.16.1.2 remote 172.16.1.1
ip -n n1 link set tun1 up
ip -n n1 addr add 10.98.0.2/24 dev tun1
ip -n n1 route add default via 10.98.0.1

ip netns exec n0 ping -i0.01 -c3 -n 10.98.0.2
ip netns exec n1 ping -i0.01 -c3 -n 10.99.0.2
