#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

. $(dirname $0)/_init.sh

port_add p0

grcli address add 10.0.0.1/24 iface p0
grcli interface add bridge br100
grcli interface add vxlan vxlan100 vni 100 local 10.0.0.1 domain br100
grcli flood vtep add 10.0.0.2 vni 100

grcli address add 192.168.100.1/24 iface br100

netns_add n1
move_to_netns x-p0 n1
ip -n n1 addr add 10.0.0.2/24 dev x-p0
ip -n n1 link add br100 type bridge
ip -n n1 link set br100 up
ip -n n1 link add vxlan100 type vxlan id 100 local 10.0.0.2 dstport 4789 dev x-p0
ip -n n1 link set vxlan100 master br100
ip -n n1 link set vxlan100 up
ip -n n1 addr add 192.168.100.2/24 dev br100
bridge -n n1 fdb add 00:00:00:00:00:00 dev vxlan100 self vni 100 dst 10.0.0.1

# Test L3 connectivity over VXLAN tunnel
# The Linux side initiates the ping which will cause grout to learn the MAC
ip netns exec n1 ping -i0.01 -c3 -W1 192.168.100.1

grcli fdb show
