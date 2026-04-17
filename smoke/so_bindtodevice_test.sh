#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

# Test SO_BINDTODEVICE on control plane TAP/TUN port representors.
#
# On NOARP TAP interfaces, the kernel sets the device own MAC as the
# neighbor hardware address (arp_constructor / ndisc_constructor).
# Grout detects this and re-injects the packet through the L3 loopback
# so the correct MAC is applied. Replies coming back from the wire are
# steered to the same TAP so SO_BINDTODEVICE sockets receive them.
#
# Scenarios covered:
#   * bind to port TAP (default VRF)
#   * bind to port TAP in a non-default VRF
#   * bind to VRF master device of a non-default VRF
#   * bind to VLAN sub-interface TAP (default and non-default VRF)
#   * no bind (baseline)
#
# Each scenario runs UDP/IPv4, UDP/IPv6, TCP/IPv4 and TCP/IPv6 echoes.

. $(dirname $0)/_init.sh

grcli interface add vrf gr-vrf1

port_add p0
port_add p1 vrf gr-vrf1
grcli interface add vlan p0.42 parent p0  vlan_id 42
grcli interface add vlan p1.43 parent p1  vlan_id 43 vrf gr-vrf1

grcli address add 172.16.0.1/24 iface p0
grcli address add fd00::1/64    iface p0
grcli address add 172.17.0.1/24 iface p1
grcli address add fd01::1/64    iface p1
grcli address add 172.18.0.1/24 iface p0.42
grcli address add fd02::1/64    iface p0.42
grcli address add 172.19.0.1/24 iface p1.43
grcli address add fd03::1/64    iface p1.43

# peer0: x-p0 + x-p0.42 (vlan 42)
netns_add peer0
move_to_netns x-p0 peer0
ip -n peer0 addr add 172.16.0.2/24 dev x-p0
ip -n peer0 addr add fd00::2/64    dev x-p0
ip -n peer0 link add link x-p0 name x-p0.42 type vlan id 42
ip -n peer0 link set x-p0.42 up
ip -n peer0 addr add 172.18.0.2/24 dev x-p0.42
ip -n peer0 addr add fd02::2/64    dev x-p0.42

# peer1: x-p1 + x-p1.43 (vlan 43, non-default VRF)
netns_add peer1
move_to_netns x-p1 peer1
ip -n peer1 addr add 172.17.0.2/24 dev x-p1
ip -n peer1 addr add fd01::2/64    dev x-p1
ip -n peer1 link add link x-p1 name x-p1.43 type vlan id 43
ip -n peer1 link set x-p1.43 up
ip -n peer1 addr add 172.19.0.2/24 dev x-p1.43
ip -n peer1 addr add fd03::2/64    dev x-p1.43

for ns in peer0 peer1; do
	ip netns exec $ns socat UDP4-LISTEN:9001,fork EXEC:'/bin/cat' &
	ip netns exec $ns socat UDP6-LISTEN:9000,fork EXEC:'/bin/cat' &
	ip netns exec $ns socat TCP4-LISTEN:9003,fork EXEC:'/bin/cat' &
	ip netns exec $ns socat TCP6-LISTEN:9002,fork EXEC:'/bin/cat' &
done
sleep 1

run_scenario() {
	local label="$1"
	local dst4="$2"
	local dst6="$3"
	local bind="$4"
	# optional explicit local src IPs, useful when binding to a VRF master:
	# the kernel would otherwise pick a src from any /32 in the VRF and
	# trip up socat's connected UDP (reply src-IP mismatch).
	local src4="${5:-}"
	local src6="${6:-}"
	local proto dst port reply src_opt
	for proto_port in "UDP4:9001" "UDP6:9000" "TCP4:9003" "TCP6:9002"; do
		proto=${proto_port%:*}
		port=${proto_port#*:}
		src_opt=""
		case "$proto" in
		*4)
			dst=$dst4
			[ -n "$src4" ] && src_opt=",bind=$src4"
			;;
		*6)
			dst="[$dst6]"
			[ -n "$src6" ] && src_opt=",bind=[$src6]"
			;;
		esac
		reply=$(echo "ping" | timeout 3 socat - "$proto:$dst:$port$src_opt$bind" 2>/dev/null) || true
		if [ "$reply" != "ping" ]; then
			fail "$label/$proto: reply not received"
		fi
	done
}

# 1. bind to port TAP in default VRF
run_scenario "bind=p0" 172.16.0.2 fd00::2 ",so-bindtodevice=p0"

# 2. bind to port TAP in non-default VRF
run_scenario "bind=p1" 172.17.0.2 fd01::2 ",so-bindtodevice=p1"

# 3. bind to VRF master device of non-default VRF.
# Explicit src IP is passed because grout only installs /32 host routes in the
# kernel (no /24 connected routes, by design: see the PBR comment in
# modules/infra/control/netlink.c). Without a src hint, the kernel picks
# arbitrarily from any /32 in the VRF, which can mismatch the destination
# subnet and break connected UDP sockets. Real FRR daemons (bgpd with
# update-source, bfdd per-session, etc.) always bind an explicit src IP for
# the same reason, so this mirrors production behaviour.
run_scenario "bind=gr-vrf1" 172.17.0.2 fd01::2 ",so-bindtodevice=gr-vrf1" 172.17.0.1 fd01::1

# 4. bind to VLAN sub-interface TAP (default VRF)
run_scenario "bind=p0.42" 172.18.0.2 fd02::2 ",so-bindtodevice=p0.42"

# 5. bind to VLAN sub-interface TAP (non-default VRF)
run_scenario "bind=p1.43" 172.19.0.2 fd03::2 ",so-bindtodevice=p1.43"

# 6. bind to VRF master, traffic flowing through the VLAN under that VRF.
# Same src-IP requirement as scenario 3 (see comment there).
run_scenario "bind=gr-vrf1/vlan" 172.19.0.2 fd03::2 ",so-bindtodevice=gr-vrf1" 172.19.0.1 fd03::1

# 7. no bind (baseline)
run_scenario "nobind" 172.16.0.2 fd00::2 ""

# 8. IPv6 link-local on port TAP. grout pushes fe80::xxx/128 (host route)
# rather than /64; this scenario verifies the daemon can still reach a
# link-local peer when the egress interface is provided via socat's
# scope_id syntax (peer_ll%p0). FRR daemons (ospf6d, etc.) do the same
# via IPV6_PKTINFO ipi6_ifindex.
peer0_ll=$(ip -n peer0 -6 addr show dev x-p0 | sed -nE 's#.*inet6 (fe80:[^/]+).*#\1#p' | head -1)
grout0_ll=$(llocal_addr p0)
[ -z "$peer0_ll" ] && fail "peer0 link-local not found on x-p0"
[ -z "$grout0_ll" ] && fail "grout link-local not found on p0"
for proto_port in "UDP6:9000" "TCP6:9002"; do
	proto=${proto_port%:*}
	port=${proto_port#*:}
	reply=$(echo "ping" | timeout 3 socat - \
		"${proto}:[${peer0_ll}%p0]:${port},so-bindtodevice=p0,bind=[${grout0_ll}]" \
		2>/dev/null) || true
	if [ "$reply" != "ping" ]; then
		fail "ll-bind=p0/${proto}: reply not received"
	fi
done
