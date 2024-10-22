# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

if [ -S "$GROUT_SOCK_PATH" ]; then
	run_grout=false
else
	run_grout=true
fi

cleanup() {
	set +e
	sh -x $tmp/cleanup
	if [ "$run_grout" = true ]; then
		kill -INT %?grout
		wait
	fi
	rm -rf -- "$tmp"
}

fail() {
	echo "fail: $*" >&2
	return 1
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=${1?builddir}
run_id=$(echo $SRANDOM$SRANDOM | base32 -w6 | tr '[:upper:]' '[:lower:]' | head -n1)

if [ "$run_grout" = true ]; then
	export GROUT_SOCK_PATH=$tmp/grout.sock
fi
export PATH=$builddir:$PATH

cat > $tmp/cleanup <<EOF
grcli show stats software
grcli show interface all
grcli show ip nexthop
grcli show ip route
grcli show ip6 nexthop
grcli show ip6 route
grcli show trace
EOF

set -x

if [ "$run_grout" = true ]; then
	grout_flags="-tv"
	if ! [ "$(basename $0)" = "config_test.sh" ]; then
		grout_flags="$grout_flags -x"
	fi
	grout $grout_flags &
fi
socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH,retry=10

grcli set trace all
