#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

wait_member_active() {
	local iface=$1
	local attempts=0
	while [ "$attempts" -lt 20 ]; do
		# Generate traffic so the Linux bridge learns grout's MAC on the
		# newly active bond member: the reply comes back via that member,
		# which is exactly what the FDB should reflect.
		ip netns exec n0 ping -c1 -W 0.2 -n 172.16.0.1 >/dev/null 2>&1 || true
		if bridge -n n0 fdb show br br0 brport "$iface" state reachable | grep -F "$mac"; then
			return 0
		fi
		sleep 0.2
		attempts=$((attempts + 1))
	done
	fail "bond member $iface not active"
}

. $(dirname $0)/_init.sh

grcli interface add bond bond0 mode active-backup

# Sub interfaces created before any member joined inherit the random address the
# bond starts with. One follows the bond, the other keeps what it was given.
vlan_mac=02:f0:00:b4:44:55
grcli interface add vlan bond0.42 parent bond0 vlan_id 42
grcli interface add vlan bond0.43 parent bond0 vlan_id 43 mac $vlan_mac

port_add p0 domain bond0
port_add p1 domain bond0
port_add p2 domain bond0

# without an explicit mac, the bond derives its address from the primary member
p0_mac=$(grcli -j interface show name p0 | jq -r .mac)
grcli -j interface show name bond0 | jq -e --arg mac "$p0_mac" 'select(.mac == $mac)' ||
	fail "bond0 mac not derived from primary member p0"

# The control plane TAP was created before any member had joined, it must
# follow, otherwise the kernel discards everything grout delivers on it.
kernel_mac=$(ip -j link show bond0 | jq -r '.[0].address')
echo "bond0 mac: grout=$p0_mac kernel=$kernel_mac"
[ "$p0_mac" = "$kernel_mac" ] || fail "bond0 mac not synced to its control plane TAP"

# The sub interface which was inheriting the bond address must follow it on its
# own TAP too, otherwise the kernel discards everything grout delivers there.
vlan42_mac=$(ip -j link show bond0.42 | jq -r '.[0].address')
echo "bond0.42 mac: kernel=$vlan42_mac (bond0=$p0_mac)"
[ "$vlan42_mac" = "$p0_mac" ] || fail "bond0.42 mac did not follow the bond"

# an address given explicitly is left alone
vlan43_mac=$(ip -j link show bond0.43 | jq -r '.[0].address')
echo "bond0.43 mac: kernel=$vlan43_mac (explicit=$vlan_mac)"
[ "$vlan43_mac" = "$vlan_mac" ] ||
	fail "bond0.43 explicit mac overwritten when the bond address changed"

mac=02:f0:00:b4:44:44

grcli interface set bond bond0 mac $mac primary p1

# an explicitly configured mac must survive a primary member change
grcli interface set bond bond0 primary p2
grcli -j interface show name bond0 | jq -e --arg mac "$mac" 'select(.mac == $mac)' ||
	fail "bond0 mac not preserved across primary member change"
grcli interface set bond bond0 primary p1

netns_add n0
ip -n n0 link add br0 type bridge vlan_filtering 1
for p in x-p0 x-p1 x-p2; do
	ip link set $p netns n0
	ip -n n0 link set $p master br0
	ip -n n0 link set $p up
done
ip -n n0 link set br0 up
ip -n n0 addr add 172.16.0.2/24 dev br0

grcli address add 172.16.0.1/24 iface bond0

wait_member_active x-p1

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1

ip -n n0 link set x-p1 down
wait_member_active x-p0

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1

ip -n n0 link set x-p1 up
wait_member_active x-p1

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1
