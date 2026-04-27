#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

# Variant of frr_restart_graceful_frr_test.sh that proves the plugin's
# t_rib_sweep control path works with the default zebra invocation
# (no -K option). Without the pre-arm of zrouter.t_rib_sweep in
# zd_grout_plugin_init, the native sweep armed by zebra_main_router_started()
# with delay=0 would race our SELFROUTE injections and produce inconsistent
# timing. The pre-arm exploits event_add_timer's *t_ptr != NULL early-return
# (lib/event.c:1430) so the native arm becomes a no-op; the plugin then
# cancels and re-arms with the proper delay after the replay marker is
# observed. This test asserts that:
#   - the route is still swept (no leak),
#   - the plugin's sync marker is observed (arm_sweep ran),
#   - marker lifecycle is clean (not in FIB, not in RIB after sweep).

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
	|| fail "prefix $prefix not installed in grout FIB"

grcli -j nexthop show | jq -e \
	".[] | select(.origin == \"zebra\" and (.info | contains(\"$nh_ip\")))" >/dev/null \
	|| fail "zebra nexthop for $nh_ip not installed in grout FIB"

# Simulate crash: SIGKILL zebra + staticd. No dplane fini runs, so
# the route stays in grout's FIB as an orphan.
pkill -9 -x zebra
pkill -9 -x staticd

for i in $(seq 1 20); do
	pgrep -x zebra >/dev/null 2>&1 || break
	sleep 0.1
done
pgrep -x zebra >/dev/null 2>&1 && fail "zebra still alive after SIGKILL"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix\")" >/dev/null \
	|| fail "prefix $prefix unexpectedly gone from grout FIB after SIGKILL"

mark_events

# Key difference vs frr_restart_graceful_frr_test.sh: we do NOT add -K to
# zebra_options. zebra_main_router_started() will try to arm t_rib_sweep
# with delay=0 (graceful_restart=false) - but zd_grout_plugin_init already
# pre-armed that slot with a long delay, so event_add_timer returns early
# and the native arm is a no-op. grout_sync_arm_sweep later cancels the
# placeholder and re-arms with delay=0 once the replay marker is seen.
frrinit.sh restart

# Sweep fires immediately without -K, route deletion event arrives fast.
# We skip the nh del assertion: without -K, the sweep races mgmtd's zapi
# apply of "nexthop-group keep 1" so the NHE keep-around defaults to 180s
# (an FRR pre-existing limitation, unrelated to this plugin fix).
wait_event -t 15 "route4 del: vrf=main $prefix"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix\")" >/dev/null \
	&& fail "prefix $prefix still in grout FIB after sweep"

# Proof that the plugin's control path ran: the marker observation log
# only appears if grout_sync_poll_marker found the marker before the
# timeout fallback.
grep -q "sync marker observed" "$flog" \
	|| fail "sync marker observation log not found: plugin control path broken"

# The sweep ran exactly once. With the pre-arm placeholder in
# zd_grout_plugin_init, zebra_main_router_started's native
# event_add_timer(..., 0, &zrouter.t_rib_sweep) is a no-op (*t_ptr
# already set); only grout_sync_arm_sweep's cancel+arm produces a real
# rib_sweep_route fire. Any count > 1 would mean the pre-arm regressed.
sweep_count=$(grep -cE 'Sweeping the RIB for stale routes\.\.\.$' "$flog" || true)
[ "$sweep_count" -eq 1 ] \
	|| fail "expected exactly 1 sweep invocation, found $sweep_count (pre-arm placeholder regressed)"

# Marker never reached grout's FIB.
grcli -j route show | jq -e \
	'.[] | select(.destination == "::/128")' >/dev/null \
	&& fail "sync marker ::/128 leaked into grout FIB"

# Marker prefix must be absent from zebra's RIB after sweep.
out=$(vtysh -c "show ipv6 route ::/128 json" 2>/dev/null)
[ -z "$out" ] || [ "$out" = "{}" ] \
	|| fail "sync marker ::/128 still in zebra RIB after sweep"

# zebra's RIB must contain exactly the static routes declared in frr.conf
# (none here - $prefix was added via vty only and must be swept).
expected=$(grep -cE '^[[:space:]]*ip route ' "$builddir/frr_install/etc/frr/frr.conf" || true)
actual=$(vtysh -c "show ip route static json" 2>/dev/null | jq 'length // 0')
[ "$expected" = "$actual" ] \
	|| fail "static route count mismatch: expected $expected from frr.conf, got $actual"

true
