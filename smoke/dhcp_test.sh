#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Anthony Harivel

# Validate that dhcpcd can configure a grout interface through the dhcpcd
# companion hook, including the default route, classless static routes and DNS.

. $(dirname $0)/_init.sh

require_tools dnsmasq dhcpcd

netns_add dhcp-server

port_add p0

move_to_netns x-p0 dhcp-server
ip -n dhcp-server addr add 192.168.100.1/24 dev x-p0

# Option 121 carries the default route and the extra static routes. When it
# is present, dhcpcd reports it in new_classless_static_routes and option 3
# must be ignored.
cat > $tmp/dnsmasq.conf <<EOF
# DHCP server configuration
interface=x-p0
bind-interfaces
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=option:classless-static-route,0.0.0.0/0,192.168.100.1,10.10.0.0/16,192.168.100.1,172.16.5.0/24,192.168.100.1
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
dhcp-option=option:domain-search,test.local
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
	grcli -j address show iface p0 |
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

has_dns() {
	[ -f "$tmp/resolv.conf" ] &&
		grep -qx 'nameserver 8.8.8.8' $tmp/resolv.conf &&
		grep -qx 'nameserver 8.8.4.4' $tmp/resolv.conf &&
		grep -qx 'search test.local' $tmp/resolv.conf
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
# reply cannot be routed to the control plane tap. dhcpcd chdirs to / and
# only passes its own PATH to hooks: the hook path must be absolute and the
# in-tree grcli directory must be added to dhcpcd's PATH.
hook=$(cd "$here/../main" && pwd)/dhcpcd-hook
grcli_dir=$(cd "$(dirname "$(command -v grcli)")" && pwd)
dhcpcd_opts=(-B -4 -J --noconfigure
	-o classless_static_routes -o domain_name_servers -o domain_search
	-c "$hook" -e RESOLV_CONF="$tmp/resolv.conf")
if [ -n "${GROUT_SOCK_PATH:-}" ]; then
	dhcpcd_opts+=(-e GROUT_SOCK_PATH="$GROUT_SOCK_PATH")
fi
# dhcpcd passes its own PATH to the hook, but not the caller's environment.
hook_path=$grcli_dir
if [ -n "$builddir" ]; then
	hook_path=$hook_path:$(cd "$builddir" && pwd)
fi
# When SELinux is enforcing dhcpcd runs in the dhcpc_t domain, which cannot
# execute the in-tree hook nor access the temporary directory. Run it
# unconfined like the grout process itself.
dhcpcd_cmd=(dhcpcd)
if command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ]; then
	require_tools runcon
	dhcpcd_cmd=(runcon -t unconfined_t dhcpcd)
fi
PATH=$hook_path:$PATH "${dhcpcd_cmd[@]}" "${dhcpcd_opts[@]}" p0 &
dhcpcd_pid=$!

cat >> $tmp/cleanup <<EOF
kill $dhcpcd_pid 2>/dev/null || true
rm -f /run/grout-dhcp.p0 /run/dhcpcd/p0*.pid /run/dhcpcd/p0*.sock
EOF

wait_for "DHCP did not assign an address to p0" has_addr
echo "lease: $(leased_addr)"

wait_for "connected route for the DHCP address is missing" has_connected_route
wait_for "DHCP did not add a default route with the dhcp origin" \
	has_route 0.0.0.0/0
wait_for "DHCP did not add the 10.10.0.0/16 static route" \
	has_route 10.10.0.0/16
wait_for "DHCP did not add the 172.16.5.0/24 static route" \
	has_route 172.16.5.0/24
wait_for "DHCP DNS servers were not written to resolv.conf" has_dns

# dhcpcd runs the hook with reason STOPPED when it exits, which removes the
# address, the routes and the DNS configuration.
kill -TERM "$dhcpcd_pid"
wait "$dhcpcd_pid" || true

wait_for "DHCP address not removed after release" no_addr
wait_for "DHCP routes not removed after release" no_dhcp_routes
if grep -q '^nameserver ' $tmp/resolv.conf; then
	fail "DHCP DNS servers not removed after release"
fi

echo "DHCP smoke test passed!"
