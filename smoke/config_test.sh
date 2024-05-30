#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

br-cli add interface port p0 devargs net_null0
br-cli add interface port p1 devargs net_null1
br-cli add ip address 10.0.0.1/24 iface p0
br-cli add ip address 10.1.0.1/24 iface p1
br-cli add ip route 0.0.0.0/0 via 10.0.0.2
br-cli show interface all
br-cli show ip route
br-cli show ip nexthop
br-cli show graph dot
br-cli show stats software
br-cli show stats hardware
