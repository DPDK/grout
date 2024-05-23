# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

cleanup() {
	set +e
	kill -INT %?br
	wait
	if [ -r $tmp/cleanup ]; then
		sh -x $tmp/cleanup
	fi
	rm -rf -- "$tmp"
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=$1

export BR_SOCK_PATH=$tmp/br.sock
export PATH=$builddir:$PATH

uid=$(base32 -w6 < /dev/urandom | tr '[:upper:]' '[:lower:]' | head -n1)

name() {
	echo "br$2-$uid-$1"
}

set -x

br -tv &
socat FILE:/dev/null UNIX-CONNECT:$BR_SOCK_PATH,retry=3
