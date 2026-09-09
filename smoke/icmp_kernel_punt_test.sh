#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy

#
# grout p0 (172.16.0.1, fd00::1) --- x-p0 (172.16.0.2, fd00::2) in n0
#
# ICMP echo replies are punted to the control plane and only delivered to the
# session that asked for them. Check that a reply nobody asked for reaches the
# kernel, so that ping(8) works through a control plane TAP.
#
. $(dirname $0)/_init.sh

port_add p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 addr add fd00::2/64 dev x-p0

grcli address add 172.16.0.1/24 iface p0
grcli address add fd00::1/64 iface p0

# wait for the IPv6 address to be usable on the control plane TAP
for _ in $(seq 50); do
	if ip -6 addr show dev p0 | grep -q "fd00::1"; then
		break
	fi
	sleep 0.1
done

# The nodebox connectivity watchdog pings its DHCP gateway only to have grout
# resolve it, then reads the nexthop state through the API and never looks at
# the ping result. Keep that sequence working.
ping -c1 -W1 -n 172.16.0.2 >/dev/null 2>&1 || true
grcli -j nexthop show internal type l3 vrf main |
	jq -e '[.[] | select(.addr == "172.16.0.2" and .state == "reachable")] | length > 0' \
	>/dev/null || fail "gateway nexthop is not reachable after pinging it"

ping -c3 -i0.2 -W1 -n 172.16.0.2 || fail "kernel ping did not receive its replies"
ping -6 -c3 -i0.2 -W1 -n fd00::2 || fail "kernel ping6 did not receive its replies"

# A socket bound to the device must get its replies on that device, so the
# reply has to go through the control plane TAP and not the VRF loopback when
# the destination address does live on the input interface.
ping -c3 -i0.2 -W1 -I p0 -n 172.16.0.2 || fail "kernel ping -I did not receive its replies"
ping -6 -c3 -i0.2 -W1 -I p0 -n fd00::2 || fail "kernel ping6 -I did not receive its replies"

# An echo reply without payload cannot be one of the builtin ping probes, which
# always carry a timestamp. It must still reach the kernel.
ping -c2 -i0.2 -W1 -s 0 -n 172.16.0.2 || fail "kernel ping -s 0 did not receive its replies"
ping -6 -c2 -i0.2 -W1 -s 0 -n fd00::2 || fail "kernel ping6 -s 0 did not receive its replies"

# Same for an ICMP error that talks about another protocol: the peer answers a
# UDP datagram sent to a closed port with a port unreachable, and the kernel
# socket must see it. This is what PMTU discovery relies on for TCP.
udp_error_reaches_socket() {
	local family=$1 addr=$2
	python3 - "$family" "$addr" <<'EOPY'
import socket, sys
family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.connect((sys.argv[2], 9))
s.settimeout(2)
s.send(b"x")
try:
    s.recv(1)
except ConnectionRefusedError:
    sys.exit(0)
except Exception:
    pass
sys.exit(1)
EOPY
}

udp_error_reaches_socket 4 172.16.0.2 ||
	fail "ICMP error about UDP did not reach the kernel socket"
udp_error_reaches_socket 6 fd00::2 ||
	fail "ICMPv6 error about UDP did not reach the kernel socket"
