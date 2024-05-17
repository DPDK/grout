# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e

cleanup() {
	set +e
	kill -INT %1
	wait
	if [ -r $tmp/cleanup ]; then
		sh -x $tmp/cleanup
	fi
	rm -rf -- "$tmp"
}

tmp=$(mktemp -d)
trap cleanup EXIT
sock=$tmp/br.sock

alias br="$1 -s $sock"
alias br-cli="$2 -s $sock"

set -x

br -tv &
socat FILE:/dev/null UNIX-CONNECT:$sock,retry=3
