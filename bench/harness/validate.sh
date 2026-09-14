#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# Dummy harness for a single bench scenario. It emulates the external element
# (starts grout in test mode and creates the two physical ports as taps),
# applies <test>.grcli, then injects <test>.py and checks that traffic is
# forwarded.
#
# Usage: sudo ./bench/harness/validate.sh <test> [builddir]
#
# Needs root: unshare, tap creation and AF_PACKET all require CAP_NET_ADMIN,
# like the smoke tests.

set -e -o pipefail

here=$(dirname $0)

# Re-exec in a private mount+net namespace for isolation and automatic cleanup.
if [ "${_BENCH_UNSHARED:-}" != 1 ]; then
	export _BENCH_UNSHARED=1
	exec unshare --mount --net -- "$0" "$@"
fi

die() {
	echo "fatal: $*" >&2
	exit 1
}

test_name="${1:?usage: $0 <test> [builddir]}"
builddir="${2:-build}"
bench_dir=$(dirname $here)

grcli_file="$bench_dir/$test_name.grcli"
traffic_file="$bench_dir/${test_name}.py"
[ -f "$grcli_file" ] || die "no such test config: $grcli_file"
[ -f "$traffic_file" ] || die "no such traffic profile: $traffic_file"

ncpu=$(nproc)
[ "$ncpu" -ge 2 ] || die "need at least 2 CPUs (control + 1 datapath)"

builddir=$(cd "$builddir" && pwd)
export PATH="$builddir:$PATH"

tmp=$(mktemp -d)
export GROUT_SOCK_PATH="$tmp/grout.sock"
export GROUT_OVERRIDE_DEFAULT_ROUTE=true
export GROUT_MAX_IFACES=64
export GROUT_MEMPOOL_CHUNK_SIZE=2047
export GROUT_MAX_NEXTHOPS=128
export GROUT_MAX_ROUTES=128
export GROUT_MAX_FDB_ENTRIES=128
export GROUT_MAX_CONNTRACKS=32
export GROUT_PORT_QUEUE_SIZE=32
export GROUT_PAGER=""

grout_pid=

cleanup() {
	status=$?
	set +e
	if [ -n "$grout_pid" ]; then
		if [ "$status" -ne 0 ]; then
			grcli trace show count 10
		fi
		kill "$grout_pid" 2>/dev/null
	fi
	rm -rf -- "$tmp"
	echo
	echo "---------- $test_name (exit $status) ----------"
	echo
	exit $status
}
trap cleanup EXIT

echo
echo "========== $test_name start =========="
echo

ip link set lo up

# --- emulate the external element -------------------------------------------
# Two-core affinity: the lowest core runs the control plane, the other runs one
# datapath worker (grout derives its worker count from the startup affinity).
cpu=$(( RANDOM % (ncpu - 1) ))
affinity="$cpu,$((cpu + 1))"

taskset -c "$affinity" grout -t >"$tmp/grout.log" 2>&1 &
grout_pid=$!

SECONDS=0
while ! socat FILE:/dev/null UNIX-CONNECT:"$GROUT_SOCK_PATH" 2>/dev/null; do
	if [ "$SECONDS" -gt 30 ]; then
		die "grout did not start: $(cat $tmp/grout.log)"
	fi
	kill -0 "$grout_pid"
	sleep 0.5
done

# Create the two physical ports as taps with a pre-sized rx queue.
for n in 0 1; do
	grcli interface add port "p$n" devargs "net_tap$n,iface=x-p$n"
	# Silence the kernel on the tap so the egress capture sees only grout.
	sysctl -qw "net.ipv6.conf.x-p$n.disable_ipv6=1"
done

# --- apply the scenario ------------------------------------------------------
grcli -xef "$grcli_file"

for n in 0 1; do
	# Kernel-side tap mac, distinct from grout's port mac (set by the .grcli),
	# so the kernel never mistakes grout's frames for its own.
	ip link set "x-p$n" address "02:00:00:0a:00:0$n"
done

# Wait for the kernel tap peers to report the link up before injecting.
for n in 0 1; do
	SECONDS=0
	while ! ip -o link show "x-p$n" | grep -qw LOWER_UP; do
		[ "$SECONDS" -gt 5 ] && break
		sleep 0.2
	done
done

# --- inject and verify -------------------------------------------------------
grcli trace enable all

export PYTHONDONTWRITEBYTECODE=x
python3 "$here/inject.py" --traffic "$traffic_file" --p0 x-p0 --p1 x-p1
