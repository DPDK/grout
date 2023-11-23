# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

builddir = build

.PHONY: all
all: $(builddir)/build.ninja
	ninja -C $(builddir)

.PHONY: all
clean:
	ninja -C $(builddir) clean

.PHONY: install
install: $(builddir)/build.ninja
	ninja -C $(builddir) install

$(builddir)/build.ninja:
	meson setup $(builddir)

src = `git ls-files '*.[ch]'`

.PHONY: lint
lint: $(builddir)/build.ninja
	clang-format --dry-run --Werror $(src)

.PHONY: format
format:
	clang-format -i --verbose $(src)
