#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# Routes are owned by the origin that installed them. Adding or deleting a
# route with a different origin must be refused so that e.g. a DHCP client
# cannot replace or remove a route installed by the user or a routing daemon.

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_tap0,iface=x-p0
grcli address add 172.16.0.1/24 iface p0
grcli address add 2001::1/64 iface p0

check_origin() {
	local dest="$1" family="$2" origin="$3"

	grcli -j route show "$family" | jq -e \
		--arg dest "$dest" --arg origin "$origin" \
		'.[] | select(.destination == $dest and .origin == $origin)' >/dev/null
}

# reserved origins are rejected by the CLI
if grcli route add 10.0.0.0/8 via 172.16.0.2 origin internal; then
	fail "expected invalid origin to be rejected"
fi
if grcli route add 10.0.0.0/8 via 172.16.0.2 origin bogus; then
	fail "expected unknown origin to be rejected"
fi

# a route can be added and re-added with its own origin
grcli route add 10.0.0.0/8 via 172.16.0.2 origin dhcp
grcli route add 10.0.0.0/8 via 172.16.0.2 origin dhcp
check_origin 10.0.0.0/8 ipv4 dhcp

# another origin cannot replace it
if grcli route add 10.0.0.0/8 via 172.16.0.3; then
	fail "expected replacing a dhcp route with a static route to fail"
fi
check_origin 10.0.0.0/8 ipv4 dhcp

# another origin cannot delete it
if grcli route del 10.0.0.0/8 origin static; then
	fail "expected deleting a dhcp route with a static origin to fail"
fi
check_origin 10.0.0.0/8 ipv4 dhcp

# the owning origin can delete it
grcli route del 10.0.0.0/8 origin dhcp
if grcli -j route show | jq -e '.[] | select(.destination == "10.0.0.0/8")' >/dev/null; then
	fail "route still present after deletion with its own origin"
fi

# omitting the origin still deletes any route
grcli route add 10.0.0.0/8 via 172.16.0.2 origin dhcp
grcli route del 10.0.0.0/8
if grcli -j route show | jq -e '.[] | select(.destination == "10.0.0.0/8")' >/dev/null; then
	fail "route still present after deletion without origin"
fi

# IPv6 uses the same ownership rules
grcli route add 2002::/16 via 2001::2 origin dhcp
check_origin 2002::/16 ipv6 dhcp
if grcli route add 2002::/16 via 2001::3; then
	fail "expected replacing a dhcp IPv6 route with a static route to fail"
fi
if grcli route del 2002::/16 origin static; then
	fail "expected deleting a dhcp IPv6 route with a static origin to fail"
fi
check_origin 2002::/16 ipv6 dhcp
grcli route del 2002::/16 origin dhcp
