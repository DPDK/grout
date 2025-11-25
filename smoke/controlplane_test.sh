#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_tap0
ip link show p0

grcli interface set port p0 mac 02:42:de:ad:be:ef mtu 1789
ip link show p0

MAC=$(ip link show p0 | awk '/\slink\/ether/ {print $2;}')
MTU=$(ip link show p0 | awk '/mtu/ {print $5;}')
if [[ $MAC != "02:42:de:ad:be:ef" ]] ; then fail "Error setting mac address" ; fi
if [[ $MTU != 1789 ]] ; then fail "Error setting mtu" ; fi
