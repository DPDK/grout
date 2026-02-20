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

# FIB config set and show
grcli interface add vrf fibtest
grcli route config set vrf fibtest fib4-size 512 fib6-size 512
grcli route config show vrf fibtest

# FIB resize with routes
grcli interface add port p5 devargs net_null2,no-rx=1 vrf fibtest
for i in $(seq 8); do
	grcli address add $i.0.0.1/24 iface p5
	grcli address add fd00:$i::1/48 iface p5
done
grcli route show vrf fibtest
count=$(grcli route show vrf fibtest | grep -wc fibtest)
[ "$count" -eq 17 ]
count=$(grcli address | grep -wc p5)
[ "$count" -eq 17 ]

# Ensure addresses were deleted
grcli route config set vrf fibtest fib4-size 1 fib6-size 8
grcli route show vrf fibtest
count=$(grcli route show vrf fibtest | grep -wc fibtest)
[ "$count" -eq 6 ]
count=$(grcli address | grep -wc p5)
[ "$count" -eq 6 ]

# cleanup
grcli interface del p5
grcli interface del fibtest
