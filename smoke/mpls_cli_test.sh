#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
grcli address add 172.16.0.1/24 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 172.16.0.2/24 dev x-p0

grcli nexthop add mpls iface p0 via 172.16.0.2 labels 100 id 10
grcli nexthop show id 10
grcli nexthop add mpls iface p0 via 172.16.0.2 labels 100 200 300 id 20
grcli nexthop show id 20
grcli nexthop add mpls iface p0 via 172.16.0.2 id 30 # pop, no labels
grcli nexthop show id 30
grcli nexthop show type mpls

grcli mpls route add 500 nexthop id 10
grcli mpls route get 500
grcli mpls route show
grcli mpls route add 500 nexthop id 10 # exist_ok
grcli mpls route del 500
grcli mpls route del 500 # missing_ok

grcli nexthop del 10
grcli nexthop del 20
grcli nexthop del 30
