# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

test_frr=true

. $(dirname $0)/_init.sh

tap_index=0
create_interface() {
	local p="$1"
	local mac="$2"

	ip link add v0-$p type veth peer name v1-$p
	grcli add interface port $p devargs net_tap$tap_index,iface=tap-$p,remote=v0-$p mac $mac

	local max_tries=5
	local count=0
	while vtysh -c "show interface $p" 2>&1 | grep -q "% Can't find interface"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Interface $p not found after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done

	tap_index=$((tap_index + 1))
}

set_ip_address() {
	local p="$1"
	local ip_cidr="$2"
	local max_tries=5
	local count=0

	if echo "$ip_cidr" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
		local gr_ip="ip6"
	else
		# IPv4
		local frr_ip="ip"
		local gr_ip="ip"
	fi

	local grep_pattern="^${p}[[:space:]]\+${ip_cidr}$"

	vtysh <<-EOF
	configure terminal
	interface ${p}
	${frr_ip} address ${ip_cidr}
	exit
EOF

	while ! grcli show ${gr_ip} address | grep -q "$grep_pattern"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "IP address $ip_cidr not set after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done
}

set_ip_route() {
	local prefix="$1"
	local next_hop="$2"
	local max_tries=5
	local count=0

	if echo "$prefix" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
		local gr_ip="ip6"
	else
		# IPv4
		local frr_ip="ip"
		local gr_ip="ip"
	fi

	local grep_pattern="^0[[:space:]]\+${prefix}[[:space:]]\+${next_hop}[[:space:]]"

	vtysh <<-EOF
	configure terminal
	${frr_ip} route ${prefix} ${next_hop}
	exit
EOF

	while ! grcli show ${gr_ip} route | grep -q "${grep_pattern}"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Route ${prefix} via ${next_hop} not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done
}
