#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

set -eu

echo ===========================================================================
git --no-pager log --oneline -1
echo ===========================================================================

# If the script was invoked without any argument (e.g. not with "lint")
# and there was any modification on .wrap files, delete the whole subproject
# folder to ensure it is prepared again by meson.
if [ "$#" -eq 0 ]; then
	for wrap in subprojects/*.wrap; do
		if ! git diff --quiet HEAD^ $wrap; then
			name=$(basename -s.wrap $wrap)
			meson subprojects purge --confirm $name
		fi
	done
fi

# Always check compilation.
time make "$@"

if [ "$#" -eq 0 ] && ! echo "$MESON_EXTRA_OPTS" | grep -q -- --cross-file; then
	# If the script was invoked without any argument (e.g. not with "lint")
	# and if we are not cross compiling, run unit and smoke tests.
	echo -------------------------------------------------------------------
	echo unit-tests
	echo -------------------------------------------------------------------
	time make unit-tests
	echo -------------------------------------------------------------------
	echo smoke-tests "($(nproc) parallel jobs)"
	echo -------------------------------------------------------------------
	time make smoke-tests -j$(nproc) -k
fi
