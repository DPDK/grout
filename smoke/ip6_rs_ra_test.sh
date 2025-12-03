#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

command -v rdisc6 || fail "rdisc6 (from ndisc6 package) is not installed"

port_add p1
grcli address add fd00:ba4:1::1/64 iface p1

netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add fd00:ba4:1::2/64 dev x-p1

sleep 3  # wait for DAD

ip netns exec n1 rdisc6 -n x-p1
