#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

echo "// SPDX-License-Identifier: BSD-3-Clause"
echo "// Copyright (c) $(date +Y) Red Hat"
echo
echo "#pragma once"
echo

for header in "$@"; do
	echo "#include <$(basename $header)>"
done | grep -v gr_api_client_impl.h | sort -u
