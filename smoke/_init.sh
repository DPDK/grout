# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e -o pipefail

: "${test_frr:=false}"

if [ -n "$ZEBRA_DEBUG_DPLANE_GROUT" ]; then
	run_frr=false
else
	run_frr=true
fi

if [ -S "$GROUT_SOCK_PATH" ]; then
	run_grout=false
else
	run_grout=true
fi

cleanup() {
	status="$?"
	set +e
	sh -x $tmp/cleanup
	# delete all non-port interfaces first
	grcli interface show |
	grep -Ev -e ^NAME -e '\<port[[:space:]]+devargs=' -e '\<loopback\>' |
	while read -r name _; do
		grcli interface del "$name"
	done
	# then delete all ports
	grcli interface show |
	grep -ve ^NAME -e '\<loopback\>' |
	while read -r name _; do
		grcli interface del "$name"
	done

	kill %?grcli
	wait %?grcli

	if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
		frrinit.sh stop
		sleep 1
		kill %?tail
		wait %?tail

		# should be already stopped
		for daemon in watchfrr.sh zebra staticd mgmtd vtysh; do
			pids=$(pgrep -f "$builddir/frr_install/.*/$daemon")
			if [ -n "$pids" ]; then
				echo "$pids" | xargs -r kill -9
			fi
		done
	fi
	if [ "$run_grout" = true ]; then
		set +x
		kill -15 "$grout_pid"
		wait "$grout_pid"
		ret="$?"
		if [ "$ret" -ne 0 ]; then
			status="$ret"
			if [ "$ret" -gt 128 ]; then
				sig=$((ret - 128))
				echo "fail: grout terminated by signal SIG$(kill -l $sig)"
			else
				echo "fail: grout exited with an error status $ret"
			fi >&2
			if [ -n "$core_pattern" ]; then
				# core dumps written to files
				for core in $tmp/core.*.*; do
					[ -f "$core" ] || continue
					gdb -c "$core" -batch \
						-ex "info threads" \
						-ex "thread apply all bt"
				done
				 # restore original core pattern
				sysctl -w kernel.core_pattern="$core_pattern"
			else
				# fallback to systemd-coredump, if available
				coredumpctl info --no-pager "$grout_pid"
			fi
		fi
		set -x
	fi
	rm -rf -- "$tmp"
	exit $status
}

fail() {
	echo "fail: $*" >&2
	return 1
}

netns_add() {
	ip netns add "$1"
	cat >> $tmp/cleanup <<EOF
ip netns pids "$1" | xargs -r kill --timeout 500 KILL
ip netns del "$1"
EOF
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=${1-}
run_id=$(echo $SRANDOM$SRANDOM | base32 -w6 | tr '[:upper:]' '[:lower:]' | head -n1)

if [ "$run_grout" = true ]; then
	export GROUT_SOCK_PATH=$tmp/grout.sock
fi
if [ -n "${builddir}" ]; then
	export PATH=$builddir:$PATH
fi

grout_extra_options=""
if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	chmod 0755 $tmp # to access on tmp
	grout_extra_options+="-m 0666"
	export ZEBRA_DEBUG_DPLANE_GROUT=1
	if [ -n "${builddir}" ]; then
		export PATH=$builddir/frr_install/sbin:$builddir/frr_install/bin:$PATH
	fi
fi

cat > $tmp/cleanup <<EOF
grcli stats show software
grcli interface show
grcli nexthop show
grcli route show
grcli trace show count 50
EOF

set -x

if [ "$run_grout" = true ]; then
	ulimit -c unlimited
	core_pattern=$(sysctl -n kernel.core_pattern)
	if ! sysctl -w kernel.core_pattern="$tmp/core.%e.%p"; then
		unset core_pattern
	fi
	export ASAN_OPTIONS=disable_coredump=0
	taskset -c 0,1 grout -tvvx $grout_extra_options &
fi
socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH,retry=10
grout_pid=$(pgrep -g0 grout)

case "$(basename $0)" in
config_test.sh|graph_svg_test.sh)
	;;
*)
	grcli trace enable all
	;;
esac

grcli events &

if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	zlog="$builddir/frr_install/var/log/frr/zebra.log"
	rm -f "$zlog"
	touch "$zlog"
	tail -f "$zlog" &
	frrinit.sh start
	timeout=15
	elapsed=0

	# wait that zebra_dplane_grout get iface event from grout
	while ! grep -q "GROUT:.*iface/ip events" "$zlog" 2>/dev/null; do
		if [ "$elapsed" -ge "$timeout" ]; then
			echo "Zebra is not listening grout event after ${timeout} seconds."
			exit 1
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
fi
