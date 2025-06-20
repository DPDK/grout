# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

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
	set +e
	sh -x $tmp/cleanup

	# delete all non-port interfaces first
	grcli show interface |
	grep -Ev -e ^NAME -e '\<port[[:space:]]+devargs=' -e '\<loopback\>' |
	while read -r name _; do
		grcli del interface "$name"
	done
	# then delete all ports
	grcli show interface |
	grep -ve ^NAME -e '\<loopback\>' |
	while read -r name _; do
		grcli del interface "$name"
	done

	kill %?grcli
	wait %?grcli

	if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
		frrinit.sh stop
		sleep 1

		# should be already stopped
		for daemon in watchfrr.sh zebra staticd mgmtd vtysh; do
			pids=$(pgrep -f "$builddir/frr_install/.*/$daemon")
			if [ -n "$pids" ]; then
				echo "$pids" | xargs -r kill -9
			fi
		done
	fi
	if [ "$run_grout" = true ]; then
		kill %?grout
		wait %?grout
	fi
	rm -rf -- "$tmp"
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
grcli show stats software
grcli show interface
grcli show nexthop
grcli show ip route
grcli show ip6 route
grcli show trace count 50
EOF

set -x

if [ "$run_grout" = true ]; then
	taskset -c 0,1 grout -tvx $grout_extra_options &
fi
socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH,retry=10

case "$(basename $0)" in
config_test.sh|graph_svg_test.sh)
	;;
*)
	grcli set trace all
	;;
esac

grcli show events &

if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	zlog="$builddir/frr_install/var/log/frr/zebra.log"
	rm -f "$zlog"
	touch "$zlog"
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
