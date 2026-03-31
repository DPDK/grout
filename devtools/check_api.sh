#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

set -eu -o pipefail

abidiff=abidiff
output=.check_api.stamp
src_dir=.
cc_cmd=cc
prev_revision=${PREV_REVISION:-HEAD^}

while getopts "d:o:c:p:s:" opt; do
	case $opt in
	d) abidiff="$OPTARG" ;;
	o) output="$OPTARG" ;;
	c) cc_cmd="$OPTARG" ;;
	p) prev_revision="$OPTARG" ;;
	s) src_dir="$OPTARG" ;;
	*) echo "error: invalid arguments" >&2; exit 1 ;;
	esac
done
shift $((OPTIND - 1))

dir=$(dirname "$output")

rm -rf "$dir/check_api"

# Install current headers to a temp dir.
install -m 644 -Dt "$dir/check_api/b" "$@"

# Install API headers from the previous revision to another dir.
mkdir -p "$dir/check_api/a"
git -C "$src_dir" ls-tree -r --name-only "$prev_revision" | grep '/meson.build$' |
while read -r meson_build; do
	git show "$prev_revision:$meson_build" |
	sed -zn 's#.*api_headers += files(\([^)]\+\)).*#\1 #p' |
	sed -n "s#,##g; s#'\\([^']\\+\\)'#$(dirname $meson_build)/\\1#gp"
done | tr ' ' '\n' | sort -u |
xargs git -C "$src_dir" archive "$prev_revision" |
tar -C "$dir/check_api/a" -x --transform='s|.*/||'

# Exclude gr_api_client_impl.h which isn't a real API header.
rm -f $dir/check_api/*/gr_api_client_impl.h

cc_cmd="$cc_cmd -fno-eliminate-unused-debug-types -Werror -O0 -g"

# Compile a dummy binary
for d in $dir/check_api/*; do
	[ -d "$d" ] || continue
	{
		cat <<EOF
#define GR_REQ(r, req, resp)                                                  \\
	resp *r##_(req *);                                                    \\
	resp *r##_(req *) {                                                   \\
		return (void *)0;                                             \\
	}

#define GR_REQ_STREAM(r, req, resp) GR_REQ(r, req, resp)

#define GR_EVENT(e, obj)                                                      \\
	obj *e##_(void);                                                      \\
	obj *e##_(void) {                                                     \\
		return (void *)0;                                             \\
	}
EOF
		basename -a $d/*.h | sed 's/.*/#include <&>/'
	} |
	$cc_cmd -c -o "$d.bin" -x c -I"$d" - || {
		echo "compilation failed: $cc_cmd" >&2
		exit 1
	}
done

printf "Checking for API changes between %s and %s\n" \
	$(git describe --long --abbrev=8 $prev_revision) \
	$(git describe --long --abbrev=8 --dirty)

if ! $abidiff --non-reachable-types --drop-private-types --show-bytes \
	--headers-dir1 $dir/check_api/a --headers-dir2 $dir/check_api/b \
	$dir/check_api/a.bin $dir/check_api/b.bin >"$dir/abidiff.log" 2>&1
then
	grep -vE '((Functions|Variables) changes|Unreachable types) summary:' "$dir/abidiff.log"
	api_version_a=$(sed -nE 's/^#define GR_API_VERSION ([0-9]+).*/\1/p' $dir/check_api/a/*.h)
	api_version_b=$(sed -nE 's/^#define GR_API_VERSION ([0-9]+).*/\1/p' $dir/check_api/b/*.h)
	if grep -q '^  \[[DC]\]' "$dir/abidiff.log"; then
		echo "breaking API changes"
		if [ "${api_version_a:-0}" -ge "${api_version_b:-0}" ]; then
			grep -n '#define GR_API_VERSION' "$@"
			echo "error: GR_API_VERSION must be incremented." >&2
			exit 1
		fi
	else
		echo "backward compatible API changes"
	fi
	if [ "$api_version_a" = "$api_version_b" ]; then
		echo "GR_API_VERSION unchanged"
	else
		echo "GR_API_VERSION changed from ${api_version_a:-0} to ${api_version_b:-0}"
	fi
fi

touch "$output"
