#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Christophe Fontaine

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.2.1/24 iface p0
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	ip -n $ns route add default via 172.16.$n.1
done

set -m

ping -i0.1 -c10 -n 172.16.0.2 &
ping -i0.01 -c3 -n 172.16.1.2

fg

# Expect these to fail
grcli route get 1.1.1.1 && fail "unknown destination resolved"
ping -c1 -W1 -n 172.16.1.3 && fail "ping to non-existent host succeeded"

traceroute -N1 -n 172.16.0.2
