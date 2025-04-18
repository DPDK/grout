# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

if [ -n "$GROUT_SOCK_NAME" ]; then
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
builddir=${1?builddir}
run_id=$(echo $SRANDOM$SRANDOM | base32 -w6 | tr '[:upper:]' '[:lower:]' | head -n1)

if [ "$run_grout" = true ]; then
	export GROUT_SOCK_NAME=$run_id-grout.sock
fi
export PATH=$builddir:$PATH

cat > $tmp/cleanup <<EOF
grcli show stats software
grcli show interface
grcli show ip nexthop
grcli show ip route
grcli show ip6 nexthop
grcli show ip6 route
grcli show trace count 50
EOF

set -x

if [ "$run_grout" = true ]; then
	taskset -c 0,1 grout -tvx &
fi
socat FILE:/dev/null ABSTRACT-CONNECT:$GROUT_SOCK_NAME,retry=10

case "$(basename $0)" in
config_test.sh|graph_svg_test.sh)
	;;
*)
	grcli set trace all
	;;
esac

grcli show events &
