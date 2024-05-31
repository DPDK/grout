# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

cleanup() {
	set +e
	sh -x $tmp/cleanup
	kill -INT %?br
	wait
	rm -rf -- "$tmp"
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=${1?builddir}
run_id=$(echo $SRANDOM$SRANDOM | base32 -w6 | tr '[:upper:]' '[:lower:]' | head -n1)

export BR_SOCK_PATH=$tmp/br.sock
export PATH=$builddir:$PATH

cat > $tmp/cleanup <<EOF
br-cli show stats software
br-cli show interface all
EOF

set -x

br -tv &
socat FILE:/dev/null UNIX-CONNECT:$BR_SOCK_PATH,retry=10
