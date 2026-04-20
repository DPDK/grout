#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

# Test TCP/UDP listeners running on grout's control plane, exercised
# from peers arriving on the matching ingress device.
#
# Mirror of so_bindtodevice_test but on the server side: the grout
# kernel runs a listener (SO_BINDTODEVICE to a specific device, or
# unbound), and a peer netns opens a connection that must reach it.
#
# Scenarios covered:
#   * listen bound to port TAP (default VRF)
#   * listen bound to port TAP in a non-default VRF
#   * listen bound to VRF master device (accepts any slave ingress)
#   * listen bound to VLAN sub-iface TAP (default and non-default VRF)
#   * unbound listen with tcp/udp_l3mdev_accept=0 (default VRF ingress)
#   * unbound listen with l3mdev_accept=0 on VRF-slave ingress (drop)
#   * unbound listen with l3mdev_accept=1 on VRF-slave ingress (accept)
#
# Each scenario runs UDP/IPv4, UDP/IPv6, TCP/IPv4 and TCP/IPv6.

. $(dirname $0)/_init.sh

grcli interface add vrf gr-vrf1

port_add p0
port_add p1 vrf gr-vrf1
grcli interface add vlan p0.42 parent p0 vlan_id 42
grcli interface add vlan p1.43 parent p1 vlan_id 43 vrf gr-vrf1

grcli address add 172.16.0.1/24 iface p0
grcli address add fd00::1/64    iface p0
grcli address add 172.17.0.1/24 iface p1
grcli address add fd01::1/64    iface p1
grcli address add 172.18.0.1/24 iface p0.42
grcli address add fd02::1/64    iface p0.42
grcli address add 172.19.0.1/24 iface p1.43
grcli address add fd03::1/64    iface p1.43

netns_add peer0
move_to_netns x-p0 peer0
ip -n peer0 addr add 172.16.0.2/24 dev x-p0
ip -n peer0 addr add fd00::2/64    dev x-p0
ip -n peer0 link add link x-p0 name x-p0.42 type vlan id 42
ip -n peer0 link set x-p0.42 up
ip -n peer0 addr add 172.18.0.2/24 dev x-p0.42
ip -n peer0 addr add fd02::2/64    dev x-p0.42

netns_add peer1
move_to_netns x-p1 peer1
ip -n peer1 addr add 172.17.0.2/24 dev x-p1
ip -n peer1 addr add fd01::2/64    dev x-p1
ip -n peer1 link add link x-p1 name x-p1.43 type vlan id 43
ip -n peer1 link set x-p1.43 up
ip -n peer1 addr add 172.19.0.2/24 dev x-p1.43
ip -n peer1 addr add fd03::2/64    dev x-p1.43

saved_tcp=$(sysctl -n net.ipv4.tcp_l3mdev_accept)
saved_udp=$(sysctl -n net.ipv4.udp_l3mdev_accept)
cat >> $tmp/cleanup <<EOF
sysctl -qw net.ipv4.tcp_l3mdev_accept=$saved_tcp
sysctl -qw net.ipv4.udp_l3mdev_accept=$saved_udp
EOF

probe() {
	local label="$1"
	local ns="$2"
	local proto="$3"      # UDP4, UDP6, TCP4 or TCP6
	local dst4="$4"
	local dst6="$5"
	local port="$6"
	local expect="$7"     # "accept" or "drop"
	local dst reply

	case "$proto" in
	*4) dst=$dst4 ;;
	*6) dst="[$dst6]" ;;
	esac

	reply=$(echo "ping" | ip netns exec "$ns" timeout 3 \
	        socat - "$proto:$dst:$port" 2>/dev/null) || true

	if [ "$expect" = "accept" ] && [ "$reply" != "ping" ]; then
		fail "$label/$proto: expected accept, got no reply"
	fi
	if [ "$expect" = "drop" ] && [ "$reply" = "ping" ]; then
		fail "$label/$proto: expected drop, got reply"
	fi
}

# Run one listen scenario: start UDP/TCP listeners with the given
# bind option, run the four probes from the given ingress, then kill
# the listeners.
#
# If $7 is "tcp-only", UDP probes are skipped. This is a limitation
# of socat UDP-LISTEN, not of the kernel or grout: the kernel accepts
# the inbound UDP packet on a VRF-slave ingress when udp_l3mdev_accept
# is set, and exposes the ingress ifindex via IP_PKTINFO ancillary
# data. socat does not read that ancillary data, so the fork'd child
# replies via the main routing table which has no route to the VRF
# peer -- sendto() returns ENETUNREACH. A real VRF-aware UDP server
# (rsyslog, FreeRADIUS, etc.) reads IP_PKTINFO and uses SO_BINDTODEVICE
# or IP_UNICAST_IF on the reply. TCP is unaffected because accept()
# hands the child socket the ingress ifindex via the inet_request_sock.
run_listen() {
	local label="$1"
	local listen_opt="$2"   # e.g. ",so-bindtodevice=p0" or ""
	local ns="$3"
	local dst4="$4"
	local dst6="$5"
	local expect="$6"
	local tcp_only="${7:-}"
	local u4 u6 t4 t6

	socat "UDP4-LISTEN:9500${listen_opt},fork"              EXEC:'/bin/cat' &
	u4=$!
	socat "UDP6-LISTEN:9501${listen_opt},fork"              EXEC:'/bin/cat' &
	u6=$!
	socat "TCP4-LISTEN:9502${listen_opt},fork,reuseaddr"    EXEC:'/bin/cat' &
	t4=$!
	socat "TCP6-LISTEN:9503${listen_opt},fork,reuseaddr"    EXEC:'/bin/cat' &
	t6=$!
	sleep 0.5

	if [ "$tcp_only" != "tcp-only" ]; then
		probe "$label" "$ns" UDP4 "$dst4" "$dst6" 9500 "$expect"
		probe "$label" "$ns" UDP6 "$dst4" "$dst6" 9501 "$expect"
	fi
	probe "$label" "$ns" TCP4 "$dst4" "$dst6" 9502 "$expect"
	probe "$label" "$ns" TCP6 "$dst4" "$dst6" 9503 "$expect"

	kill "$u4" "$u6" "$t4" "$t6" 2>/dev/null || true
	wait "$u4" "$u6" "$t4" "$t6" 2>/dev/null || true
	sleep 0.3
}

# 1. listen on port TAP in default VRF
run_listen "listen=p0" ",so-bindtodevice=p0" \
	peer0 172.16.0.1 fd00::1 accept

# 2. listen on port TAP in non-default VRF
run_listen "listen=p1" ",so-bindtodevice=p1" \
	peer1 172.17.0.1 fd01::1 accept

# 3. listen on VRF master device: accepts from any slave of gr-vrf1
run_listen "listen=gr-vrf1" ",so-bindtodevice=gr-vrf1" \
	peer1 172.17.0.1 fd01::1 accept

# 4. listen on VLAN sub-iface TAP (default VRF)
run_listen "listen=p0.42" ",so-bindtodevice=p0.42" \
	peer0 172.18.0.1 fd02::1 accept

# 5. listen on VLAN sub-iface TAP (non-default VRF)
run_listen "listen=p1.43" ",so-bindtodevice=p1.43" \
	peer1 172.19.0.1 fd03::1 accept

# 6. unbound listen from default VRF ingress: always accepts
sysctl -qw net.ipv4.tcp_l3mdev_accept=0
sysctl -qw net.ipv4.udp_l3mdev_accept=0
run_listen "nobind/default" "" \
	peer0 172.16.0.1 fd00::1 accept

# 7. unbound listen from VRF-slave ingress with l3mdev_accept=0: drops.
# TCP only: UDP silent-drop vs timeout is indistinguishable here, but
# the scenario is primarily about verifying the l3mdev gate.
run_listen "nobind/l3mdev=0/vrf" "" \
	peer1 172.17.0.1 fd01::1 drop tcp-only

# 8. unbound listen from VRF-slave ingress with l3mdev_accept=1: accepts.
# TCP only: the UDP reply from an unbound socket cannot be routed
# back to the VRF peer (see run_listen comment).
sysctl -qw net.ipv4.tcp_l3mdev_accept=1
sysctl -qw net.ipv4.udp_l3mdev_accept=1
run_listen "nobind/l3mdev=1/vrf" "" \
	peer1 172.17.0.1 fd01::1 accept tcp-only
