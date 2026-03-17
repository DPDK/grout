#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile, Iliad
#
# Wrapper to run system tcpdump with grout's libpcap (DPDK pdump support).
#
# This is a temporary workaround until libpcap merges the DPDK pdump
# capture module upstream and Linux distributions enable it at compile
# time. Track progress at:
#   https://github.com/the-tcpdump-group/libpcap/pull/1656
#
# Once distributions ship a libpcap with PCAP_SUPPORT_DPDK_PDUMP,
# this script is no longer needed — tcpdump will natively support
# "grout:N" devices.
#
# Usage: sudo ./subprojects/packagefiles/libpcap/grout-tcpdump.sh -i grout:0 -n

SCRIPT="$(readlink -f "$0")"
BASEDIR="$(dirname "$SCRIPT")/../../.."
LIBPCAP_DIR="$BASEDIR/build/libpcap-build"
DPDK_LIBDIR="$BASEDIR/build/subprojects/dpdk/lib"
DPDK_DRVDIR="$BASEDIR/build/subprojects/dpdk/drivers"

if [ ! -f "$LIBPCAP_DIR/libpcap.so" ]; then
	echo "error: $LIBPCAP_DIR/libpcap.so not found, build grout first" >&2
	exit 1
fi

# Our libpcap.so.0.8 symlink is found before the system one.
export LD_LIBRARY_PATH="$LIBPCAP_DIR:$DPDK_LIBDIR:$DPDK_DRVDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Tell the DPDK secondary process where to find PMD drivers.
# The compiled-in path (RTE_EAL_PMD_PATH) points to an install prefix
# that doesn't exist in a development build tree.
export DPDK_CFG="--proc-type=secondary -l0 --no-telemetry --log-level=critical -d $DPDK_DRVDIR"

exec tcpdump "$@"
