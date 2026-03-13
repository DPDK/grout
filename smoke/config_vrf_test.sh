#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

. $(dirname $0)/_init.sh

# VRF delete with interfaces should fail
grcli interface add vrf testvrf
grcli interface add port p4 devargs net_null2,no-rx=1 vrf testvrf
grcli interface del testvrf && fail "del VRF with interfaces should fail"
grcli interface del p4
grcli interface del testvrf

# reserved name rejection
grcli interface add port gr-loop99 devargs net_null2,no-rx=1 \
	&& fail "reserved name gr-loop99 should be rejected"
grcli interface add vrf gr-loop99 \
	&& fail "reserved name gr-loop99 should be rejected for VRF"
grcli interface add vrf main \
	&& fail "reserved name main should be rejected for non-default VRF"

# VRF rename
grcli interface add vrf renameme
grcli interface set vrf renameme name renamed
grcli interface show name renamed
ip link show renamed
grcli interface del renamed

# default VRF rename and rename back
grcli interface add port p4 devargs net_null2,no-rx=1
grcli interface set vrf main name tmpname
grcli interface show name tmpname
ip link show tmpname
grcli interface set vrf tmpname name main
grcli interface show name main
ip link show main
grcli interface del p4

# FIB config defaults
grcli route config show

# FIB config: create VRF with custom FIB sizes
grcli interface add vrf fibtest rib4-routes 512 rib6-routes 512
grcli route config show vrf fibtest

# FIB config: verify VRF show displays FIB config
grcli -j interface show name fibtest \
	| jq -e '.rib4_max_routes == 512' || fail "rib4_max_routes should be 512"
grcli -j interface show name fibtest \
	| jq -e '.rib6_max_routes == 512' || fail "rib6_max_routes should be 512"

# FIB config: reconfigure VRF FIB sizes via iface set
grcli interface set vrf fibtest rib4-routes 1024
grcli -j interface show name fibtest \
	| jq -e '.rib4_max_routes == 1024' || fail "rib4_max_routes should be 1024 after set"

# FIB resize with routes
grcli interface add port p5 devargs net_null2,no-rx=1 vrf fibtest
for i in $(seq 8); do
	grcli address add $i.0.0.1/24 iface p5
	grcli address add fd00:$i::1/48 iface p5
done
grcli route show vrf fibtest
count=$(grcli -j route show vrf fibtest | jq length)
[ "$count" -eq 17 ]

# FIB resize via iface set with tbl8 override
grcli interface set vrf fibtest fib4-tbl8 64
grcli -j interface show name fibtest \
	| jq -e '.fib4_num_tbl8 == 64' || fail "fib4_num_tbl8 should be 64"
grcli -j interface show name fibtest \
	| jq -e '.rib4_max_routes == 1024' || fail "rib4_max_routes should still be 1024 after tbl8 set"

# Ensure routes survived resize (same max_routes)
count=$(grcli -j route show vrf fibtest | jq length)
[ "$count" -eq 17 ]

# Ensure tbl8 is auto-derived when max_routes changes
grcli interface set vrf fibtest rib4-routes 2048
grcli -j interface show name fibtest \
	| jq -e '.rib4_max_routes == 2048' || fail "rib4_max_routes should be 2048"
grcli -j interface show name fibtest \
	| jq -e '.fib4_num_tbl8 != 64' || fail "fib4_num_tbl8 should be auto-derived after max_routes change"

# Ensure routes and addresses were dropped on resize down
grcli interface set vrf fibtest rib4-routes 1 rib6-routes 8
grcli route config show vrf fibtest
grcli route show vrf fibtest
count=$(grcli -j route show vrf fibtest | jq length)
[ "$count" -eq 9 ]

# FIB config set default max_routes
grcli route config set default rib4-routes 256 rib6-routes 256
grcli interface add vrf newvrf
grcli -j interface show name newvrf \
	| jq -e '.rib4_max_routes == 256' || fail "rib4_max_routes should be 256 (inherited default)"
grcli -j interface show name newvrf \
	| jq -e '.rib6_max_routes == 256' || fail "rib6_max_routes should be 256 (inherited default)"
grcli route config show vrf newvrf

# FIB reconfig on VRF created without FIB params
grcli interface set vrf newvrf rib4-routes 128
grcli -j interface show name newvrf \
	| jq -e '.rib4_max_routes == 128' || fail "rib4_max_routes should be 128 after set on default VRF"

# cleanup
grcli interface del p5
grcli interface del fibtest
grcli interface del newvrf
