# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

builddir = build

.PHONY: all
all:: $(builddir)/build.ninja
	ninja -C $(builddir)

$(builddir)/build.ninja: meson.build
	meson setup $(builddir)

src = `git ls-files '*.[ch]'`

lint:
	clang-format --dry-run --Werror $(src)
	ninja -C $(builddir) scan-build

format:
	clang-format -i --verbose $(src)
