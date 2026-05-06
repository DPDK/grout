#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile

. $(dirname $0)/_init.sh

tcpdump --version

port_add p0
port_add p1
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

# per-interface capture produces valid pcapng with ICMP packets
mark_events
cap=$tmp/capture-p0.pcapng
timeout 5 grcli capture iface p0 count 10 > "$cap" &
cap_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2
wait $cap_pid

[ -s "$cap" ] || fail "capture file is empty"
tcpdump -r "$cap" -n -c1 || fail "tcpdump cannot read pcapng"
tcpdump -r "$cap" -n | grep ICMP || fail "no ICMP packets in capture"

# all-interfaces capture sees traffic on both ports
mark_events
cap_all=$tmp/capture-all.pcapng
timeout 5 grcli capture any count 10 > "$cap_all" &
cap_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c5 -n 172.16.1.2
ip netns exec n1 ping -i0.01 -c5 -n 172.16.0.2
wait $cap_pid

[ -s "$cap_all" ] || fail "all-interfaces capture file is empty"
tcpdump -r "$cap_all" -n | grep ICMP || fail "no ICMP in all-iface capture"

# killing the capture process frees the session for reuse
mark_events
cap_reuse=$tmp/capture-reuse.pcapng
timeout 5 grcli capture iface p0 count 5 > "$cap_reuse" &
cap_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c5 -n 172.16.0.1
wait $cap_pid

[ -s "$cap_reuse" ] || fail "restarted capture file is empty"

# concurrent captures on different interfaces
mark_events
cap_first=$tmp/capture-first.pcapng
cap_second=$tmp/capture-second.pcapng
timeout 5 grcli capture iface p0 count 5 > "$cap_first" &
cap_pid_first=$!
timeout 5 grcli capture iface p1 count 5 > "$cap_second" &
cap_pid_second=$!
wait_event -c2 "capture start"

ip netns exec n0 ping -i0.01 -c5 -n 172.16.1.2
wait $cap_pid_first
wait $cap_pid_second

[ -s "$cap_first" ] || fail "first concurrent capture file is empty"
[ -s "$cap_second" ] || fail "second concurrent capture file is empty"
tcpdump -r "$cap_first" -n | grep ICMP || fail "no ICMP in first concurrent capture"
tcpdump -r "$cap_second" -n | grep ICMP || fail "no ICMP in second concurrent capture"

# second capture on the same interface must fail
mark_events
timeout 5 grcli capture iface p0 >/dev/null &
cap_pid=$!
wait_event "capture start"

if grcli capture iface p0 count 1 >/dev/null; then
	fail "duplicate capture on same iface should fail"
fi
kill $cap_pid
wait $cap_pid

# snaplen truncation produces valid pcapng
mark_events
cap_snap=$tmp/capture-snap.pcapng
timeout 5 grcli capture iface p0 count 5 snaplen 64 > "$cap_snap" &
cap_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c5 -s 500 -n 172.16.1.2
wait $cap_pid

[ -s "$cap_snap" ] || fail "snaplen capture file is empty"
tcpdump -r "$cap_snap" -n -c1 || fail "tcpdump cannot read snaplen pcapng"

# grcli capture with BPF filter
mark_events
cap_filter=$tmp/capture-filter.pcapng
timeout 5 grcli capture iface p0 count 5 filter icmp > "$cap_filter" &
cap_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c5 -n 172.16.1.2
ip netns exec n0 bash -c 'for i in $(seq 1 10); do echo x > /dev/udp/172.16.1.2/9999 2>/dev/null; done'
wait $cap_pid

[ -s "$cap_filter" ] || fail "filtered capture file is empty"
tcpdump -r "$cap_filter" -n | grep ICMP || fail "no ICMP in filtered capture"
if tcpdump -r "$cap_filter" -n | grep UDP; then
	fail "UDP leaked through BPF filter"
fi

# native tcpdump captures ICMP on a single interface
mark_events
cap_native=$tmp/capture-native.pcapng
timeout 5 tcpdump -i grout:p0 -w "$cap_native" -c5 &
td_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2
wait $td_pid 2>/dev/null || true

[ -s "$cap_native" ] || fail "native tcpdump capture is empty"
tcpdump -r "$cap_native" -n | grep ICMP || fail "no ICMP in native tcpdump capture"

# native tcpdump -D lists grout interfaces
tcpdump -D | grep "grout:p0" || fail "grout:p0 not listed by tcpdump -D"

# native tcpdump on grout:any captures traffic
mark_events
cap_native_all=$tmp/capture-native-all.pcapng
timeout 5 tcpdump -i grout:any -w "$cap_native_all" -c5 &
td_pid=$!
wait_event "capture start"

ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2
wait $td_pid 2>/dev/null || true

[ -s "$cap_native_all" ] || fail "native tcpdump all-capture is empty"
tcpdump -r "$cap_native_all" -n | grep ICMP || fail "no ICMP in native all-capture"

# native tcpdump with BPF filter
mark_events
cap_bpf=$tmp/capture-bpf.pcapng
timeout 5 tcpdump -i grout:p0 -w "$cap_bpf" 'icmp' -c5 &
td_pid=$!
wait_event "capture start"

ip netns exec n0 bash -c 'for i in $(seq 1 20); do echo x > /dev/udp/172.16.1.2/9999 2>/dev/null; done' &
udp_pid=$!
ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2 &
ping_pid=$!
wait $ping_pid $udp_pid $td_pid

[ -s "$cap_bpf" ] || fail "BPF filtered capture is empty"
tcpdump -r "$cap_bpf" -n | grep ICMP || fail "no ICMP in BPF filtered capture"
if tcpdump -r "$cap_bpf" -n | grep UDP; then
	fail "UDP leaked through BPF filter"
fi
