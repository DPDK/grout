#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

# ICMPv6 errors sent to the source of the packets that cannot be forwarded.

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add fd00:ba4:0::1/64 iface p0
grcli address add fd00:ba4:1::1/64 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add fd00:ba4:$n::2/64 dev $p
	ip -n $ns route add default via fd00:ba4:$n::1
done

ip netns exec n0 ping -i0.01 -c3 -n fd00:ba4:1::2

# capture_error TYPE COMMAND...
capture_error() {
	local type="$1" pid
	shift
	mark_events
	timeout 10 grcli capture iface p0 direction out count 1 \
		filter "ip6[40]=$type" > $tmp/error.pcapng &
	pid=$!
	wait_event -t10 "capture start"
	"$@" && fail "unexpected success: $*"
	wait $pid || fail "no ICMPv6 error of type $type"
	tcpdump -r $tmp/error.pcapng -nv | tee $tmp/error.txt
}

# A large invoking packet is truncated: the error is 1280 bytes long.
capture_error 3 ip netns exec n0 ping -c1 -W1 -t1 -s 1400 -n fd00:ba4:1::2
grep -qF 'payload length: 1240' $tmp/error.txt || fail "error larger than the minimum MTU"
# A small one is copied as a whole.
capture_error 3 ip netns exec n0 ping -c1 -W1 -t1 -n fd00:ba4:1::2
grep -qF 'payload length: 112' $tmp/error.txt || fail "invoking packet not copied as a whole"
