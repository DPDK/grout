#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

here=$(dirname $0)
builddir=${1?build dir}
log=$(mktemp)
result=0
trap "if [ -s $log ]; then cat $log; fi; rm -f $log" EXIT

run() {
	local script="$1"
	local res=0
	return $res
}

for script in $here/*_test.sh; do
	name=$(basename $script)
	printf "%s ... " "$name"
	start=$(date +%s)
	res=OK

	{
		echo "====================================================="
		echo "+$script $builddir"
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
