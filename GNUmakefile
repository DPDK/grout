# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

builddir = build
ifeq ($V,1)
ninja_opts = --verbose
Q =
else
Q = @
endif

.PHONY: all
all: $(builddir)/build.ninja
	$Q ninja -C $(builddir) $(ninja_opts)

.PHONY: test
test: $(builddir)/build.ninja
	$Q ninja -C $(builddir) test $(ninja_opts)

.PHONY: coverage
coverage: test
	$Q mkdir -p $(builddir)/coverage
	$Q gcovr --html-details $(builddir)/coverage/index.html --txt \
		-e '.*stb_ds.*' -e '.*_test.c' -ur . $(builddir)
	@echo Coverage data is present in $(builddir)/coverage/index.html

.PHONY: all
clean:
	$Q ninja -C $(builddir) clean $(ninja_opts)

.PHONY: install
install: $(builddir)/build.ninja
	$Q ninja -C $(builddir) install $(ninja_opts)

meson_opts = \
	--buildtype=debug \
	--werror \
	--warnlevel=2 \
	-Db_sanitize=address

$(builddir)/build.ninja:
	$Q meson setup $(builddir) $(meson_opts)

prune = -path $1 -prune -o
exclude = $(builddir) subprojects LICENSE .git README.md main/include/stb_ds.h
c_src = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -name '*.[ch]' -print`
all_files = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -print`

.PHONY: lint
lint: $(builddir)/build.ninja
	@echo '[clang-format]'
	$Q clang-format --dry-run --Werror $(c_src)
	@echo '[license-check]'
	$Q ! for f in $(all_files); do \
		if ! grep -qF 'SPDX-License-Identifier: BSD-3-Clause' $$f; then \
			echo $$f; \
		fi; \
		if ! grep -q 'Copyright .* [0-9]\{4\} .*' $$f; then \
			echo $$f; \
		fi; \
	done | LC_ALL=C sort -u | grep --color . || { \
		echo 'error: files are missing license and/or copyright notice'; \
		exit 1; \
	}

.PHONY: format
format:
	@echo '[clang-format]'
	$Q clang-format -i --verbose $(c_src)
