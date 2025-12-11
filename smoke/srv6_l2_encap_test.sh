#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

# Using 5f00::/16 as reserved for SRv6
FUNC_DX2_NS0=5f00::
FUNC_DX2_NS1=5f00:1::

port_add p0
port_add p1 mtu 1600

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
done

ip -n n0 addr add 172.16.0.2/24 dev x-p0
grcli address add 2001:db8:1::1/64 iface p1
ip -n n1 addr add 2001:db8:1::2/64 dev x-p1

netns_add n2
ip link add veth0 type veth peer name veth1
ip link set netns n1 dev veth0
ip -n n1 link set veth0 up

ip link set netns n2 dev veth1
ip -n n2 link set veth1 up

ip -n n2 addr add 172.16.0.1/24 dev veth1

grcli nexthop add srv6 seglist $FUNC_DX2_NS1 encap h.encaps id 26
grcli interface set port p0 mode srv6-l2vpn 26

grcli nexthop add srv6-local behavior end.dx2 p0 id 2
grcli route add $FUNC_DX2_NS0/64 via id 2
grcli route add $FUNC_DX2_NS1/64 via 2001:db8:1::2

ip netns exec n1 sysctl -wq net.ipv6.conf.all.accept_dad=0
ip netns exec n1 sysctl -wq net.ipv6.conf.default.accept_dad=0
ip netns exec n1 sysctl -wq net.ipv6.conf.all.forwarding=1
ip netns exec n1 sysctl -wq net.ipv4.conf.all.rp_filter=0
ip netns exec n1 sysctl -wq net.ipv4.conf.default.rp_filter=0
ip netns exec n1 sysctl -wq net.ipv4.conf.all.forwarding=1
ip netns exec n1 sysctl -wq net.ipv4.ip_forward=1

ip -n n1 -6 route add $FUNC_DX2_NS1/128 encap seg6local action End.DX2 oif veth0 dev x-p1
ip -n n1 -6 route add $FUNC_DX2_NS0/128 via 2001:db8:1::1
ip -n n1 -6 route add ::/0 via 2001:db8:1::1

ip netns exec n1 python3 smoke/srv6_l2_encap_scapy.py &
SCAPY_PID=$!
sleep 3

# Verify the scapy script is running
if ! kill -0 $SCAPY_PID 2>/dev/null; then
    echo "ERROR: SRv6 encapsulation script failed to start"
    exit 1
fi

ip netns exec n0 ping -i0.1 -c3 172.16.0.1
