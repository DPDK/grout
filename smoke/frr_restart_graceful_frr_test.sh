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
nh_ip=172.16.0.2

create_interface p0
set_ip_address p0 172.16.0.1/24

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add ${nh_ip}/24 dev x-p0

# The *_orphan entries stay vty-only: their install vanishes from
# staticd memory after SIGKILL, the plugin's SELFROUTE placeholders
# end up unreclaimed and swept. The *_kept entries are also written
# to frr.conf via --persist so staticd rehydrates them via mgmtd at
# restart and rib_compare_routes transfers ownership of the
# SELFROUTE entries to ZEBRA_ROUTE_STATIC.
set_ip_route $prefix_orphan $nh_ip
set_ip_route --persist $prefix_kept $nh_ip


grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	|| fail "prefix $prefix_orphan not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "prefix $prefix_kept not installed in grout FIB"

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

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	&& fail "$prefix_orphan still in grout FIB after sweep"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "$prefix_kept unexpectedly gone from grout FIB after sweep (reclaim broken)"

# In zebra's RIB the reclaimed prefix must be ZEBRA_ROUTE_STATIC, not
# kernel/self: rib_compare_routes transferred ownership from the
# plugin's SELFROUTE injection to staticd's re-push.
vtysh -c "show ip route $prefix_kept" 2>/dev/null \
	| grep -qE 'Known via "static"' \
	|| fail "$prefix_kept is not a static route in zebra RIB after reclaim"

# Marker must not leak into the dataplane.
grcli -j route show | jq -e \
	'.[] | select(.destination == "::/128")' >/dev/null \
	&& fail "sync marker ::/128 leaked into grout FIB"

out=$(vtysh -c "show ipv6 route ::/128 json" 2>/dev/null)
[ -z "$out" ] || [ "$out" = "{}" ] \
	|| fail "sync marker ::/128 still in zebra RIB after sweep"

# zebra's RIB must contain exactly the static routes declared in frr.conf
# ($prefix_kept was appended; $prefix_orphan was vty-only and must be swept).
expected=$(grep -cE '^[[:space:]]*ip route ' "$builddir/frr_install/etc/frr/frr.conf" || true)
actual=$(vtysh -c "show ip route static json" 2>/dev/null | jq 'length // 0')
[ "$expected" = "$actual" ] \
	|| fail "static route count mismatch: expected $expected from frr.conf, got $actual"

# Sweep ran exactly once: the placeholder pre-arm in zd_grout_plugin_init
# neutralised zebra_main_router_started's native arm (event_add_timer
# *t_ptr != NULL early-return), and grout_sync_arm_sweep's cancel + arm
# is the only fire. Any count > 1 means the pre-arm trick regressed.
sweep_count=$(tail -n +$((frr_log_mark + 1)) "$frr_log" \
	| grep -cE 'Sweeping the RIB for stale routes\.\.\.$' || true)
[ "$sweep_count" -eq 1 ] \
	|| fail "expected exactly 1 sweep invocation, found $sweep_count (pre-arm placeholder regressed)"

true
