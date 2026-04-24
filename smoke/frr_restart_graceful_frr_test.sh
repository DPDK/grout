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

. $(dirname $0)/_init_frr.sh

prefix_orphan=10.99.99.0/24
prefix_kept=10.88.88.0/24
nh_ip=172.16.0.2

create_interface p0
set_ip_address p0 172.16.0.1/24

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add ${nh_ip}/24 dev x-p0

set_ip_route $prefix_orphan $nh_ip
set_ip_route $prefix_kept $nh_ip

# Persist $prefix_kept to frr.conf so staticd rehydrates it at restart.
# $prefix_orphan is deliberately left out: its vty-only install vanishes
# from staticd's memory after SIGKILL and the plugin's SELFROUTE
# placeholder ends up unreclaimed.
echo "ip route $prefix_kept $nh_ip" >> "$builddir/frr_install/etc/frr/frr.conf"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	|| fail "prefix $prefix_orphan not installed in grout FIB"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "prefix $prefix_kept not installed in grout FIB"

# Simulate crash: SIGKILL zebra + staticd. No dplane fini runs, both
# routes stay in grout's FIB as orphans.
pkill -9 -x zebra
pkill -9 -x staticd

for i in $(seq 1 20); do
	pgrep -x zebra >/dev/null 2>&1 || break
	sleep 0.1
done
pgrep -x zebra >/dev/null 2>&1 && fail "zebra still alive after SIGKILL"

grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_orphan\")" >/dev/null \
	|| fail "$prefix_orphan unexpectedly gone from grout FIB after SIGKILL"
grcli -j route show | jq -e \
	".[] | select(.destination == \"$prefix_kept\")" >/dev/null \
	|| fail "$prefix_kept unexpectedly gone from grout FIB after SIGKILL"

mark_events

# -K 5: graceful restart window. Gives staticd time to read frr.conf,
# reconnect zapi, and re-push $prefix_kept before the sweep fires.
# nexthop-group keep 1 so the orphan NHE cleanup fits the test window.
sed -i 's/zebra_options="\(.*\)"/zebra_options="\1 -K5"/' \
	"$builddir/frr_install/etc/frr/daemons"
echo "zebra nexthop-group keep 1" >> "$builddir/frr_install/etc/frr/frr.conf"

frrinit.sh restart

# Orphan gets swept, reclaimed route must NOT emit a grout del event.
wait_event -t 15 "route4 del: vrf=main $prefix_orphan"

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

# Marker lifecycle assertions (same as sweep-only test).
grep -q "sync marker observed" "$flog" \
	|| fail "sync marker observation log not found in $flog"

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
sweep_count=$(grep -cE 'Sweeping the RIB for stale routes\.\.\.$' "$flog" || true)
[ "$sweep_count" -eq 1 ] \
	|| fail "expected exactly 1 sweep invocation, found $sweep_count (pre-arm placeholder regressed)"

true
