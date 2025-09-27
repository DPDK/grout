#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

svg_to_edges() {
	grep -A1 'class="edge"' | sed -En 's,^<title>(.+)</title>$,\1,p' |
	sed 's/&#45;&gt;/ -> /' | LC_ALL=C sort -u
}

. $(dirname $0)/_init.sh

command -v dot || fail "graphviz is not installed"

# compare runtime graph with the image stored in git
svg_to_edges < docs/graph.svg > $tmp/edges_git
grcli show graph | dot -Tsvg | svg_to_edges > $tmp/edges_runtime
diff -u $tmp/edges_git $tmp/edges_runtime || fail "docs/graph.svg is not up to date"
