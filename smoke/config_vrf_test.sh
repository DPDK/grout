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
grcli interface add port p4 devargs net_null2,no-rx=1 name gr-loop99 \
	&& fail "reserved name gr-loop99 should be rejected"
grcli interface add vrf gr-loop99 \
	&& fail "reserved name gr-loop99 should be rejected for VRF"
grcli interface add vrf main \
	&& fail "reserved name main should be rejected for non-default VRF"

# VRF rename
grcli interface add vrf renameme
grcli interface set vrf renameme name renamed
grcli interface show | grep -q renamed || fail "VRF should be renamed"
ip link show renamed || fail "kernel VRF device should be renamed"
grcli interface del renamed

# default VRF rename and rename back
grcli interface add port p4 devargs net_null2,no-rx=1
grcli interface set vrf main name tmpname
grcli interface show | grep -q tmpname || fail "default VRF should be renamed"
ip link show tmpname || fail "kernel TUN device should be renamed"
grcli interface set vrf tmpname name main
grcli interface show | grep -q main || fail "default VRF should be renamed back to main"
ip link show main || fail "kernel TUN device should be renamed back"
grcli interface del p4
