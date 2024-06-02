# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

if [ -S "$BR_SOCK_PATH" ]; then
	run_br=false
else
	run_br=true
fi

cleanup() {
	set +e
	sh -x $tmp/cleanup
	if [ "$run_br" = true ]; then
		kill -INT %?br
		wait
	fi
	rm -rf -- "$tmp"
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=${1?builddir}
run_id=$(echo $SRANDOM$SRANDOM | base32 -w6 | tr '[:upper:]' '[:lower:]' | head -n1)

if [ "$run_br" = true ]; then
	export BR_SOCK_PATH=$tmp/br.sock
fi
export PATH=$builddir:$PATH

cat > $tmp/cleanup <<EOF
br-cli show stats software
br-cli show interface all
br-cli show ip nexthop
EOF

set -x

if [ "$run_br" = true ]; then
	br -tv &
fi
socat FILE:/dev/null UNIX-CONNECT:$BR_SOCK_PATH,retry=10
