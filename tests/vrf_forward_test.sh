#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

. $(dirname $0)/_init.sh

p0=$(name 0)
p1=$(name 1)
p2=$(name 2)
p3=$(name 3)

br-cli -xe <<EOF
add interface port $p0 devargs net_tap0,iface=$p0 vrf 1
add interface port $p1 devargs net_tap1,iface=$p1 vrf 1
add interface port $p2 devargs net_tap2,iface=$p2 vrf 2
add interface port $p3 devargs net_tap3,iface=$p3 vrf 2
add ip address 10.0.0.1/16 iface $p0
add ip address 10.1.0.1/16 iface $p1
add ip address 10.0.0.1/16 iface $p2
add ip address 10.1.0.1/16 iface $p3
show ip address vrf 1
show ip address vrf 2
EOF

for n in 0 1 2 3; do
	p=$(name $n)
	ip netns add $p
	echo ip netns del $p >> $tmp/cleanup
	ip link set $p netns $p
	ip -n $p link set $p up
	ip -n $p addr add 10.$((n % 2)).0.2/16 dev $p
	ip -n $p route add default via 10.$((n % 2)).0.1
done

tcpdump_opts="--immediate-mode --no-promiscuous-mode"

timeout 3 ip netns exec $p1 \
	tcpdump $tcpdump_opts -c 3 -i $p1 icmp[icmptype] == icmp-echoreply &
sleep 1
ip netns exec $p0 ping -i0.01 -c3 10.1.0.2
wait -f %?tcpdump

timeout 3 ip netns exec $p3 \
	tcpdump $tcpdump_opts -c 3 -i $p3 icmp[icmptype] == icmp-echoreply &
sleep 1
ip netns exec $p2 ping -i0.01 -c3 10.1.0.2
wait -f %?tcpdump

br-cli -xe <<EOF
show ip route vrf 1
show ip route vrf 2
show ip nexthop vrf 1
show ip nexthop vrf 2
EOF
