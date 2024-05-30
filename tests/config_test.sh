#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

br-cli -xe <<EOF
add interface port p0 devargs net_null0
add interface port p1 devargs net_null1
add ip address 10.0.0.1/24 iface p0
add ip address 10.1.0.1/24 iface p1
add ip route 0.0.0.0/0 via 10.0.0.2
show interface all
show ip route
show ip nexthop
show graph dot
show stats software
show stats hardware
EOF
