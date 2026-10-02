#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

# Verify the FRR staticd → dplane_grout → grout MPLS LSP path for two cases:
#   1. PHP (implicit-null): in-label 100, grout pops and forwards to n1
#   2. Label swap: in-label 100 → out-label 200, grout swaps and n1 pops
#
#  .-------..--------------.
#  | zebra ||    grout     |
#  '-------'|              |
#  .-------.|.-----..------..
#  |staticd|||  p0 ||  p1  ||
#  '-------'||  172||  172 ||
#           ||16.0.1|16.1.1||
#  .----------------.  .-----------.
#  |       n0       |  |    n1     |
#  | 172.16.0.2/24  |  |172.16.1.2 |
#  | push MPLS 100  |  |10.0.1.1/lo|
#  '----------------'  '-----------'
#
# PHP flow:
#   n0 --[label 100]--> grout --[pop]--> n1 (10.0.1.1)
# Swap flow:
#   n0 --[label 100]--> grout --[swap→200]--> n1 --[kernel pop 200]--> lo

. $(dirname $0)/_init_frr.sh

create_interface p0
create_interface p1

set_ip_address p0 172.16.0.1/24
set_ip_address p1 172.16.1.1/24

netns_add n0
netns_add n1
move_to_netns x-p0 n0
move_to_netns x-p1 n1

ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n1 addr add 172.16.1.2/24 dev x-p1
ip -n n1 addr add 10.0.1.1/32 dev lo

# n1: reply path for pings originating from n0 (172.16.0.2)
ip -n n1 route add 172.16.0.0/24 via 172.16.1.1

# grout: IP route to 10.0.1.0/24 so that after PHP it can forward to n1
set_ip_route 10.0.1.0/24 172.16.1.2

# Install MPLS LSP via FRR staticd: in-label 100, PHP (implicit-null) via 172.16.1.2
_apply_frr_config 0 \
	"mpls route add: vrf=main label=100 .* origin=zebra_static" \
	"mpls lsp 100 172.16.1.2 implicit-null"

# n0: push MPLS label 100 for traffic to 10.0.1.0/24 via grout
ip netns exec n0 sysctl -wq net.mpls.platform_labels=1000
ip -n n0 route add 10.0.1.0/24 encap mpls 100 via 172.16.0.1

# n0 sends MPLS-labeled packet, grout pops label 100 (PHP) and forwards to n1
ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1

# Remove LSP and verify removal event
_apply_frr_config 0 \
	"mpls route del: vrf=main label=100 .* origin=zebra_static" \
	"no mpls lsp 100 172.16.1.2 implicit-null"

# Label swap: in-label 100 → out-label 200 via 172.16.1.2
# n1 needs kernel MPLS to accept and pop label 200 on ingress
ip netns exec n1 sysctl -wq net.mpls.platform_labels=1000
ip netns exec n1 sysctl -wq net.mpls.conf.x-p1.input=1
ip -n n1 -f mpls route add 200 dev lo

_apply_frr_config 0 \
	"mpls route add: vrf=main label=100 .* origin=zebra_static" \
	"mpls lsp 100 172.16.1.2 200"

# n0 sends MPLS label 100, grout swaps to 200, n1 pops and delivers to lo
ip netns exec n0 ping -i0.01 -c3 -n 10.0.1.1

# Remove swap LSP
_apply_frr_config 0 \
	"mpls route del: vrf=main label=100 .* origin=zebra_static" \
	"no mpls lsp 100 172.16.1.2 200"
