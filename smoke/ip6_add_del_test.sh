#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

p0=${run_id}0

grcli add interface port $p0 devargs net_tap0,iface=$p0 mac f0:0d:ac:dc:00:00

grcli add ip6 address 2001::1/64 iface $p0
grcli show ip6 address
grcli del ip6 address 2001::1/64 iface $p0
grcli show ip6 address
