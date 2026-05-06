#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

# Grout restart test: grout is SIGKILL'd while FRR keeps running, then
# respawned with a fresh empty FIB (simulating initd auto-restart in a
# real deployment). The plugin detects the broken socket, calls
# grout_ns_reset which wipes zebra's RIB via vrf_terminate(), then
# resyncs from the repopulated grout. staticd (still alive across the
# crash) re-pushes its route via zapi once the interface comes back up.
#
# Complements frr_restart_graceful_frr_test.sh which covers the
# opposite direction (zebra crash while grout survives). Here we
# validate that zebra's RIB and grout's FIB reconverge without manual
# intervention after a grout crash.

. $(dirname $0)/_init_frr.sh

prefix=10.99.99.0/24
nh_ip=172.16.0.2

create_interface p0
set_ip_address p0 172.16.0.1/24

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add ${nh_ip}/24 dev x-p0

set_ip_route $prefix $nh_ip

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix\")" >/dev/null \
	|| fail "prefix $prefix not in grout FIB pre-crash"

vtysh -c "show ip route $prefix" 2>/dev/null \
	| grep -qE 'Known via "static"' \
	|| fail "$prefix not a static route in zebra RIB pre-crash"

# Simulate grout crash. initd would respawn grout in a real
# deployment; restart_grout does the equivalent here.
restart_grout

# Replay what initd's post-restart script does in prod: recreate the
# port and re-assign the address. The plugin is expected to detect
# the reconnect, wipe zebra's RIB via vrf_terminate, then resync from
# this repopulated grout. staticd (still alive across the grout
# crash) re-pushes its route via zapi once the nexthop becomes
# resolvable again.
grcli route config set default rib4-routes 128 rib6-routes 128
grcli interface add port p0 devargs net_tap0,iface=x-p0
grcli address add 172.16.0.1/24 iface p0

# Wait for the plugin's resync to finish: the static route pushed by
# staticd (which survived the crash) should reappear in grout's FIB
# once the plugin has replayed ifaces/addrs and staticd has re-pushed
# via zapi.
wait_event -t 30 "route4 add: vrf=main $prefix"

vtysh -c "show ip route $prefix" 2>/dev/null \
	| grep -qE 'Known via "static"' \
	|| fail "$prefix not reclaimed as static in zebra RIB after resync"

true
