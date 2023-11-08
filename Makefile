# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

builddir = build

.PHONY: all
all: $(builddir)/brouter

$(builddir)/brouter: $(builddir)/build.ninja
	ninja -C $(builddir)

$(builddir)/build.ninja: meson.build
	meson setup $(builddir)

src = `git ls-files '*.[ch]'`

lint:
	@clang-format --dry-run --Werror $(src)

format:
	@clang-format -i --verbose $(src)
