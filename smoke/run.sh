#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -eu

here=$(dirname $0)
skip_patterns=()
log=$(mktemp)
result=0

while [ $# -gt 0 ]; do
	case "$1" in
	-s|--skip)
		shift
		skip_patterns+=("$1")
		;;
	-*)
		echo "error: invalid option: $1" >&2
		exit 1
		;;
	*)
		builddir="$1"
	esac
	shift
done

skip_test() {
	local name=$1
	for pattern in "${skip_patterns[@]}"; do
		case "$name" in
		$pattern)
			return 0
			;;
		esac
	done
	return 1
}

test_frr=false
# running test frr is only supported when grout is built, not installed
if [ -n "${builddir+x}" ] && \
	   jq -e '.[] | select(.name == "frr" and .value == "enabled")' \
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
	if skip_test "$name"; then
		echo "SKIPPED"
		continue
	fi
	start=$(date +%s)
	res=OK

	{
		echo "====================================================="
		echo "+ $script $builddir"
		if ! "$script" "$builddir"; then
			res=FAILED
		fi
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
