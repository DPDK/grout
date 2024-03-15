# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

BUILDDIR ?= build
BUILDTYPE ?= debugoptimized
SANITIZE ?= none
V ?= 0
ifeq ($V,1)
ninja_opts = --verbose
Q =
else
Q = @
endif

.PHONY: all
all: $(BUILDDIR)/build.ninja
	$Q ninja -C $(BUILDDIR) $(ninja_opts)

.PHONY: test
test: $(BUILDDIR)/build.ninja
	$Q ninja -C $(BUILDDIR) test $(ninja_opts)

.PHONY: coverage
coverage: test
	$Q mkdir -p $(BUILDDIR)/coverage
	$Q gcovr --html-details $(BUILDDIR)/coverage/index.html --txt \
		-e '.*stb_ds.*' -e '.*_test.c' -ur . $(BUILDDIR)
	@echo Coverage data is present in $(BUILDDIR)/coverage/index.html

.PHONY: all
clean:
	$Q ninja -C $(BUILDDIR) clean $(ninja_opts)

.PHONY: install
install: $(BUILDDIR)/build.ninja
	$Q ninja -C $(BUILDDIR) install $(ninja_opts)

meson_opts := --buildtype=$(BUILDTYPE) --werror --warnlevel=2 -Db_sanitize=$(SANITIZE)

$(BUILDDIR)/build.ninja:
	meson setup $(BUILDDIR) $(meson_opts)

prune = -path $1 -prune -o
exclude = $(BUILDDIR) subprojects LICENSE .git README.md .lsan-suppressions main/include/stb_ds.h
c_src = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -name '*.[ch]' -print`
all_files = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -print`

.PHONY: lint
lint: $(BUILDDIR)/build.ninja
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
