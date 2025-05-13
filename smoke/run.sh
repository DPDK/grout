#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

here=$(dirname $0)
if [ "$1" = "--coredump" ]; then
	coredump=true
	ulimit -c unlimited
	trap "sysctl -qw 'kernel.core_pattern=$(sysctl -n kernel.core_pattern)'" EXIT
	sysctl -qw kernel.core_pattern=/tmp/grout-core.%e.%p
	shift
fi
builddir=${1?build dir}
log=$(mktemp)
result=0

run() {
	local script="$1"
	local res=0
	return $res
}

test_frr=false
if jq -e \
  '.[] | select(.name == "frr" and .value == "enabled")' \
  "$builddir/meson-info/intro-buildoptions.json" >/dev/null 2>&1; then
	test_frr=true
fi

for script in $here/*_test.sh; do
	name=$(basename $script)
	case "$name" in
	*_frr_test.sh)
		[ "$test_frr" = true ] || continue
		;;
	esac

	printf "%s ... " "$name"
	start=$(date +%s)
	res=OK

	{
		echo "====================================================="
		echo "+ $script $builddir"
		if ! "$script" "$builddir"; then
			res=FAILED
		fi
		for core in /tmp/grout-core.*.*; do
			[ -s "$core" ] || continue
			binary=$(file -b "$core" | sed -En "s/.*, execfn: '([^']+)',.*/\\1/p")
			[ -x "$binary" ] || continue
			gdb -ex 'info threads' \
				-ex 'thread apply all bt full' \
				-ex 'quit' \
				"$binary" -c "$core" || true
			rm -f "$core"
		done
		end=$(date +%s)
		duration=$(date -d "@$((end - start))" "+%Mm%Ss")
		echo "-----------------------------------------------------"
		printf '%s %s (%s)\n' "$name" "$res" "$duration"
		echo "-----------------------------------------------------"
	} >$log 2>&1

	if [ "$res" = FAILED ]; then
		result=1
		echo
		cat $log
		rm -f $log
	else
		printf 'OK (%s)\n' "$duration"
	fi
done

exit $result
