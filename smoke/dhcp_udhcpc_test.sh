#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# Validate that busybox udhcpc can configure a grout interface through the
# udhcpc companion script, including the default route from option 3.

. $(dirname $0)/_init.sh

require_tools dnsmasq udhcpc

netns_add dhcp-server

# The companion scripts keep their state in /run/grout-dhcp.<iface> which is
# not isolated by the test mount namespace. Use a different interface name
# than dhcp_test.sh: smoke tests run in parallel.
port_add p1

move_to_netns x-p1 dhcp-server
ip -n dhcp-server addr add 192.168.100.1/24 dev x-p1

# The udhcpc script only installs the default route from option 3. Option 121
# is not exported by udhcpc and must not be required to get a default route.
cat > $tmp/dnsmasq.conf <<EOF
# DHCP server configuration
interface=x-p1
bind-interfaces
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=option:router,192.168.100.1
dhcp-authoritative
log-dhcp
no-daemon
EOF

ip netns exec dhcp-server dnsmasq \
	--conf-file=$tmp/dnsmasq.conf \
	--log-facility=$tmp/dnsmasq.log \
	--pid-file=$tmp/dnsmasq.pid &

cat >> $tmp/cleanup <<EOF
[ -f $tmp/dnsmasq.pid ] && kill \$(cat $tmp/dnsmasq.pid) 2>/dev/null || true
EOF

# Wait for dnsmasq to start
sleep 1

leased_addr() {
	grcli -j address show iface p1 |
		jq -r '.[] | select(.address | startswith("192.168.100.")) | .address'
}

has_addr() {
	[ -n "$(leased_addr)" ]
}

no_addr() {
	[ -z "$(leased_addr)" ]
}

has_route() {
	grcli -j route show ipv4 | jq -e --arg dest "$1" '.[] |
		select(.destination == $dest and
		       .origin == "dhcp" and
		       (.next_hop | contains("192.168.100.1")))' >/dev/null
}

has_connected_route() {
	grcli -j route show ipv4 |
		jq -e '.[] | select(.destination == "192.168.100.0/24")' >/dev/null
}

no_dhcp_routes() {
	[ -z "$(grcli -j route show ipv4 |
		jq -r '.[] | select(.origin == "dhcp") | .destination')" ]
}

wait_for() {
	local what=$1
	shift

	SECONDS=0
	until "$@"; do
		[ "$SECONDS" -gt 10 ] && fail "$what"
		sleep 0.2
	done
}

# The client must run in the same network namespace as grout, on the control
# plane tap which has the same name as the grout interface. Ask the server to
# broadcast its replies: until the address is configured in grout, a unicast
# reply cannot be routed to the control plane tap. Unlike dhcpcd, udhcpc passes
# its own environment to the script, GROUT_SOCK_PATH and PATH are inherited.
script=$(cd "$here/../main" && pwd)/udhcpc-script
# -f keeps udhcpc in the foreground, -R makes it release the lease and run the
# script with deconfig on SIGTERM.
udhcpc -f -B -R -i p1 -s "$script" &
udhcpc_pid=$!

cat >> $tmp/cleanup <<EOF
kill $udhcpc_pid 2>/dev/null || true
rm -f /run/grout-dhcp.p1
EOF

wait_for "DHCP did not assign an address to p1" has_addr
echo "lease: $(leased_addr)"

wait_for "connected route for the DHCP address is missing" has_connected_route
wait_for "DHCP did not add a default route with the dhcp origin" \
	has_route 0.0.0.0/0

kill -TERM "$udhcpc_pid"
wait "$udhcpc_pid" || true

wait_for "DHCP address not removed after release" no_addr
wait_for "DHCP routes not removed after release" no_dhcp_routes

echo "DHCP udhcpc smoke test passed!"
