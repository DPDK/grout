#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Christophe Fontaine

. $(dirname $0)/_init.sh

p0=${run_id}0
p1=${run_id}1

for n in 0 1; do
	p=$run_id$n
	port_add $p 40$n
	grcli address add 172.16.$n.1/24 iface $p
	netns_add $p 40$n
	ip -n $p addr add 172.16.$n.2/24 dev $p
	ip -n $p route add default via 172.16.$n.1
done
grcli address add 172.16.2.1/24 iface $p0

set -m

grcli ping 172.16.0.2 count 10 delay 100 &
grcli ping 172.16.1.2 count 3 delay 10

fg

# Expect this test to fail
grcli ping 1.1.1.1 count 1 && fail "ping to unknown route succeeded"
grcli ping 172.16.1.3 count 1 && fail "ping to non-existent host succeeded"

grcli traceroute 172.16.0.2
