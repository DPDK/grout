#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

here=$(dirname $0)
builddir=${1-}
log=$(mktemp)
result=0

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
