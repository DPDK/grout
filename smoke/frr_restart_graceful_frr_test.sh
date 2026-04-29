#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Maxime Leroy, Free Mobile

# Graceful restart test: zebra is killed along with its clients while
# grout keeps running. On restart with -K 5 the plugin re-injects the
# orphan routes as SELFROUTE; staticd (re-reading the persisted config)
# re-pushes the static route via zapi. rib_compare_routes transfers
# ownership of the reclaimed route. At T0+5 rib_sweep_route fires:
# the orphan route is purged, the reclaimed one survives.
#
# zd_grout_plugin_init pre-arms zrouter.t_rib_sweep with a long delay so
# zebra_main_router_started()'s own event_add_timer(rib_sweep_route, K,
# &zrouter.t_rib_sweep) is a no-op (*t_ptr != NULL early-return,
# lib/event.c:1430). grout_sync_arm_sweep replaces the placeholder with
# the real clamped delay once the replay marker is observed.
#
# Follows the pattern of FRR upstream tests/topotests/zebra_graceful_restart
# (PR 21550) but uses staticd with two prefixes instead of sharpd+staticd:
#   - $prefix_orphan: installed via vtysh runtime only, never persisted;
#                     staticd loses it on restart, plugin's SELFROUTE
#                     placeholder is never reclaimed, sweep wipes it.
#   - $prefix_kept:   installed via vtysh AND appended to frr.conf so
#                     staticd rehydrates it at restart and re-pushes via
#                     zapi within the -K window. rib_compare_routes
#                     promotes the SELFROUTE entry to ZEBRA_ROUTE_STATIC;
#                     the sweep predicate no longer matches and the
#                     route survives.

# -K5: graceful restart window so staticd can re-push $prefix_kept
# before the sweep fires. Set BEFORE start_frr so watchfrr caches the
# args and respawns zebra with -K5 after the simulated crash.
export ZEBRA_EXTRA_OPTS="-K5"

# Watchfrr's default min-restart-interval is 60s, which silently postpones
# zebra's respawn after SIGKILL well beyond any sane test timeout. Drop
# it to 1s so the respawn is observable within the 10s pid-change poll.
export WATCHFRR_EXTRA_OPTS="--min-restart-interval=1"

. $(dirname $0)/_init_frr.sh

prefix_orphan=10.99.99.0/24
prefix_kept=10.88.88.0/24
sr6_orphan=192.168.99.0/24
sr6_kept=192.168.88.0/24
sr6_orphan_sid=fd00:202:100::
sr6_kept_sid=fd00:202:200::
sr6_localsid_orphan=fd00:202:300::
sr6_localsid_kept=fd00:202:400::
nh_ip=172.16.0.2
nh6_ip=fd00:102::2

# A second VRF is required so the two SR6_LOCAL SIDs land in distinct
# (behavior, vrf) contexts in zebra's SRv6 manager. With a single VRF
# the second sid request would release the first one rather than
# coexist.
create_vrf vrf2

create_interface p0
set_ip_address p0 172.16.0.1/24
set_ip_address p0 fd00:102::1/64

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add ${nh_ip}/24 dev x-p0
ip -n n0 addr add ${nh6_ip}/64 dev x-p0

# The *_orphan entries stay vty-only: their install vanishes from
# staticd memory after SIGKILL, the plugin's SELFROUTE placeholders
# end up unreclaimed and swept. The *_kept entries are also written
# to frr.conf via --persist so staticd rehydrates them via mgmtd at
# restart and rib_compare_routes transfers ownership of the
# SELFROUTE entries to ZEBRA_ROUTE_STATIC.
set_ip_route $prefix_orphan $nh_ip
set_ip_route --persist $prefix_kept $nh_ip

# Reachability for the SID block + SR6_OUTPUT prefixes.
set_ip_route --persist fd00:202::/32 $nh6_ip
# L3VPN shape: customer prefix in vrf2, encap nexthop on p0 in default.
# This is the cross-vrf encap case (route.vrf != nh.vrf) that the dump
# path must preserve through restart; without the gr_r4->vrf_id fix in
# rt_grout.c, the prefix gets re-injected into zebra's main vrf at
# startup and sweep then misses the real entry in grout's vrf2.
set_srv6_route $sr6_orphan p0 vrf2 default $sr6_orphan_sid
set_srv6_route --persist $sr6_kept p0 vrf2 default $sr6_kept_sid

# SR6_LOCAL static-SIDs. Two SIDs need two distinct (behavior, vrf)
# contexts: the orphan decaps into the default VRF, the kept one
# into vrf2. Only the kept SID is persisted to frr.conf.
set_srv6_localsid loc1 fd00:202 $sr6_localsid_orphan
set_srv6_localsid --persist loc1 fd00:202 $sr6_localsid_kept end.dt4 vrf2

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	|| fail "prefix $prefix_orphan not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "prefix $prefix_kept not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_orphan\")" >/dev/null \
	|| fail "prefix $sr6_orphan not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_kept\")" >/dev/null \
	|| fail "prefix $sr6_kept not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_localsid_orphan/48\")" >/dev/null \
	|| fail "static-SID $sr6_localsid_orphan/48 not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_localsid_kept/48\")" >/dev/null \
	|| fail "static-SID $sr6_localsid_kept/48 not installed in grout FIB"

mark_events
# Mark frr_log so the marker wait skips start_frr's earlier emission.
frr_log_mark=$(wc -l < "$frr_log")

# Simulate crash: SIGKILL zebra + staticd. Watchfrr respawns them with
# the cached argv (zebra_options="... -K5" from ZEBRA_EXTRA_OPTS at the
# top of this test), so the new zebra honours the graceful restart
# window.
kill_frr_daemons zebra staticd

# Gate 1: end-of-sync (marker observed = arm_sweep ran, timer armed).
{ tail -f -n +$((frr_log_mark + 1)) "$frr_log" || : ; } | \
	timeout 20 grep -m 1 -E "sync marker observed" >/dev/null \
	|| fail "timeout 20s waiting for FRR sync marker after restart"

# Gate 2: sweep actually fired (covers 5s -K + event loop config replay).
{ tail -f -n +$((frr_log_mark + 1)) "$frr_log" || : ; } | \
	timeout 15 grep -m 1 -E "Sweeping the RIB for stale routes" >/dev/null \
	|| fail "timeout 15s waiting for rib_sweep_route to fire"

# Del events propagate to grout in <1s. Reclaimed routes must NOT emit a del.
wait_event -t 3 "route4 del: vrf=main $prefix_orphan"
wait_event -t 3 "route4 del: vrf=vrf2 $sr6_orphan"
wait_event -t 3 "route6 del: vrf=main $sr6_localsid_orphan/48"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	&& fail "$prefix_orphan still in grout FIB after sweep"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_orphan\")" >/dev/null \
	&& fail "$sr6_orphan still in grout FIB after sweep"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_localsid_orphan/48\")" >/dev/null \
	&& fail "$sr6_localsid_orphan/48 still in grout FIB after sweep"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "$prefix_kept unexpectedly gone from grout FIB after sweep (reclaim broken)"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_kept\")" >/dev/null \
	|| fail "$sr6_kept unexpectedly gone from grout FIB after sweep (SR6 reclaim broken)"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$sr6_localsid_kept/48\")" >/dev/null \
	|| fail "$sr6_localsid_kept/48 unexpectedly gone from grout FIB after sweep (SR6_LOCAL reclaim broken)"

# In zebra's RIB the reclaimed prefix must be ZEBRA_ROUTE_STATIC, not
# kernel/self: rib_compare_routes transferred ownership from the
# plugin's SELFROUTE injection to staticd's re-push.
vtysh -c "show ip route $prefix_kept" 2>/dev/null \
	| grep -qE 'Known via "static"' \
	|| fail "$prefix_kept is not a static route in zebra RIB after reclaim"
vtysh -c "show ip route vrf vrf2 $sr6_kept" 2>/dev/null \
	| grep -qE 'Known via "static"' \
	|| fail "$sr6_kept is not a static route in zebra vrf2 RIB after reclaim"
vtysh -c "show ip route vrf vrf2 $sr6_kept json" 2>/dev/null \
	| jq -e ".\"$sr6_kept\"[].nexthops[] | select(.seg6.segs == \"$sr6_kept_sid\")" \
	>/dev/null \
	|| fail "$sr6_kept lost its seg6 SID after reclaim"

# Marker must not leak into the dataplane.
grcli -j route show | jq -e \
	'.[] | select(.destination == "::/128")' >/dev/null \
	&& fail "sync marker ::/128 leaked into grout FIB"

out=$(vtysh -c "show ipv6 route ::/128 json" 2>/dev/null)
[ -z "$out" ] || [ "$out" = "{}" ] \
	|| fail "sync marker ::/128 still in zebra RIB after sweep"

# zebra's RIB must contain exactly the static routes declared in frr.conf
# ($prefix_kept was appended; $prefix_orphan was vty-only and must be swept).
# Count across all VRFs since the SR6 L3VPN entry lives in vrf2.
expected=$(grep -cE '^[[:space:]]*ip route ' "$builddir/frr_install/etc/frr/frr.conf" || true)
actual_default=$(vtysh -c "show ip route static json" 2>/dev/null | jq 'length // 0')
actual_vrf2=$(vtysh -c "show ip route vrf vrf2 static json" 2>/dev/null | jq 'length // 0')
actual=$((actual_default + actual_vrf2))
[ "$expected" = "$actual" ] \
	|| fail "static route count mismatch: expected $expected from frr.conf, got $actual (default=$actual_default vrf2=$actual_vrf2)"

# Sweep ran exactly once: the placeholder pre-arm in zd_grout_plugin_init
# neutralised zebra_main_router_started's native arm (event_add_timer
# *t_ptr != NULL early-return), and grout_sync_arm_sweep's cancel + arm
# is the only fire. Any count > 1 means the pre-arm trick regressed.
sweep_count=$(tail -n +$((frr_log_mark + 1)) "$frr_log" \
	| grep -cE 'Sweeping the RIB for stale routes\.\.\.$' || true)
[ "$sweep_count" -eq 1 ] \
	|| fail "expected exactly 1 sweep invocation, found $sweep_count (pre-arm placeholder regressed)"

true
