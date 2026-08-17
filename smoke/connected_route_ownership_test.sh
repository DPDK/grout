#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Harrison Caldicott

# A routing daemon can briefly replay a protocol route for a prefix that is
# owned by an interface address. Both the add and the later withdrawal must
# be refused with EBUSY so that the address-owned connected route stays
# authoritative. Link-local prefixes are stored under interface-scoped RIB
# keys and must be protected by the same guard.

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_tap0,iface=x-p0
grcli address add 172.16.0.1/24 iface p0
grcli address add 2001::1/64 iface p0

# protocol-style add and delete of address-owned prefixes must be refused
if grcli route add 172.16.0.0/24 via 172.16.0.2; then
	fail "expected EBUSY adding over an address-owned route"
fi
if grcli route del 172.16.0.0/24; then
	fail "expected EBUSY deleting an address-owned route"
fi
if grcli route add 2001::/64 via 2001::2; then
	fail "expected EBUSY adding over an address-owned IPv6 route"
fi
if grcli route del 2001::/64; then
	fail "expected EBUSY deleting an address-owned IPv6 route"
fi
if grcli route add fe80::/64 via 2001::2; then
	fail "expected EBUSY adding over the link-local connected route"
fi

grcli -j route show | jq -e \
	'.[] | select(.destination == "172.16.0.0/24" and .origin == "link")' >/dev/null
grcli -j route show | jq -e \
	'.[] | select(.destination == "2001::/64" and .origin == "link")' >/dev/null
grcli -j route show | jq -e \
	'.[] | select((.destination | startswith("fe80")) and .origin == "link")' >/dev/null

# prefixes merely covered by a connected subnet are not address-owned
grcli route add 172.16.0.128/25 via 172.16.0.2
grcli -j route show | jq -e \
	'.[] | select(.destination == "172.16.0.128/25" and .origin == "static")' >/dev/null
grcli route del 172.16.0.128/25
grcli route add 2001:0:0:0:8000::/65 via 2001::2
grcli route del 2001:0:0:0:8000::/65

# removing the address is the one legitimate path that reclaims the routes
grcli address del 172.16.0.1/24 iface p0
if grcli -j route show | jq -e \
	'.[] | select(.destination == "172.16.0.0/24")' >/dev/null; then
	fail "connected route still present after address del"
fi
grcli address del 2001::1/64 iface p0
if grcli -j route show | jq -e \
	'.[] | select(.destination == "2001::/64")' >/dev/null; then
	fail "IPv6 connected route still present after address del"
fi
