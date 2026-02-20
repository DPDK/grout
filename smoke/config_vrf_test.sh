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
