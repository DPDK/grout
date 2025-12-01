#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

set -eu

echo ===========================================================================
git --no-pager log --oneline -1
echo ===========================================================================

# If there was any modification on .wrap files, delete the whole subproject
# folder to ensure it is prepared again by meson.
for wrap in subprojects/*.wrap; do
	if ! git diff --quiet HEAD^ $wrap; then
		rm -rf "${wrap%.wrap}"
	fi
done

# Always check compilation.
make "$@"

if [ "$#" -eq 0 ] && ! echo "$MESON_EXTRA_OPTS" | grep -q -- --cross-file; then
	# If the script was invoked without any argument (e.g. not with "lint")
	# and if we are not cross compiling, run unit and smoke tests.
	echo -------------------------------------------------------------------
	echo unit-tests
	echo -------------------------------------------------------------------
	make unit-tests
	echo -------------------------------------------------------------------
	echo smoke-tests
	echo -------------------------------------------------------------------
	sudo make smoke-tests
fi
