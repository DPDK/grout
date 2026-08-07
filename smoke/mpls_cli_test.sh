#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

. $(dirname $0)/_init.sh

port_add p0
grcli address add 172.16.0.1/24 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 172.16.0.2/24 dev x-p0

# create MPLS nexthop with single label
grcli nexthop add mpls iface p0 via 172.16.0.2 labels 100 id 10

# verify nexthop is visible
grcli nexthop show id 10

# create MPLS nexthop with multiple labels
grcli nexthop add mpls iface p0 via 172.16.0.2 labels 100 200 300 id 20

# verify multi-label nexthop
grcli nexthop show id 20

# create pop nexthop (no labels)
grcli nexthop add mpls iface p0 via 172.16.0.2 id 30

# verify pop nexthop
grcli nexthop show id 30

# list MPLS nexthops
grcli nexthop show type mpls

# add label route
grcli mpls route add 500 nexthop id 10

# get label route
grcli mpls route get 500

# list label routes
grcli mpls route show

# idempotent add (exist_ok)
grcli mpls route add 500 nexthop id 10

# delete label route
grcli mpls route del 500

# idempotent delete (missing_ok)
grcli mpls route del 500

# cleanup nexthops
grcli nexthop del 10
grcli nexthop del 20
grcli nexthop del 30
