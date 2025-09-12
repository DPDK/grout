#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Maxime Leroy, Free Mobile

set -eu

# $1 = built .so, $2 = destination .so, $3 = daemons file, $4 = stamp file
install -D -m 755 "$1" "$2"
sed -i -e '/^zebra_options=/ {
             /-M[[:space:]]*dplane_grout/! s/"$/ -M dplane_grout"/
           }' "$3"
touch "$4"
