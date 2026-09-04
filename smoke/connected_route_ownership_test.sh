#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Harrison Caldicott

# A routing daemon can briefly replay a connected prefix before it has learned
# the interface address. The add must not replace the address-owned connected
# route and the subsequent withdrawal must be refused with EBUSY.

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_tap0,iface=x-p0
grcli address add 172.16.0.1/24 iface p0
grcli address add 2001::1/64 iface p0

grcli route add 172.16.0.0/24 via 172.16.0.2
if grcli route del 172.16.0.0/24; then
	fail "expected EBUSY deleting an address-owned route"
fi
grcli route add 2001::/64 via 2001::2
if grcli route del 2001::/64; then
	fail "expected EBUSY deleting an address-owned IPv6 route"
fi

grcli -j route show | jq -e \
	'.[] | select(.destination == "172.16.0.0/24" and .origin == "link")' >/dev/null
grcli -j route show | jq -e \
	'.[] | select(.destination == "2001::/64" and .origin == "link")' >/dev/null
