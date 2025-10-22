#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

set -xe -o pipefail

: ${PREFIX:=/usr}
: ${SYSCONFDIR:=/etc}
: ${LIBDIR:=/usr/lib64}
: ${SBINDIR:=/usr/lib/frr}
: ${LIBEXECDIR:=/usr/libexec}
: ${LOCALSTATEDIR:=/run/frr}
: ${YANGMODELSDIR:=/usr/share/frr-yang}

frr_url=$(sed -n 's/url = //p' subprojects/frr.wrap)
frr_tag=$(sed -n 's/revision = //p' subprojects/frr.wrap)

git clone --depth=1 --branch="$frr_tag" "$frr_url" frr_build
cd frr_build
curl -L https://github.com/FRRouting/frr/pull/19351.diff | patch -p1
autoreconf -ivf
./configure \
	--prefix="$PREFIX" \
	--sysconfdir="$SYSCONFDIR" \
	--libdir="$LIBDIR" \
	--libexecdir="$LIBEXECDIR" \
	--localstatedir="$LOCALSTATEDIR" \
	--sbindir="$SBINDIR" \
	--with-moduledir="$LIBDIR/frr/modules" \
	--with-yangmodelsdir="$YANGMODELSDIR" \
	--disable-doc --enable-multipath=1 \
	--disable-ripd --disable-ripngd --disable-ospfd --disable-ospf6d \
	--disable-ldpd --disable-nhrpd --disable-eigrpd --disable-babeld \
	--disable-isisd --disable-pimd --disable-pim6d --disable-pbrd \
	--disable-fabricd --disable-vrrpd --disable-pathd --disable-ospfapi \
	--disable-ospfclient --disable-bfdd --disable-python-runtime
make -j install
