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

.PHONY: unit-tests
unit-tests: $(BUILDDIR)/build.ninja
	$Q ninja -C $(BUILDDIR) test $(ninja_opts)

.PHONY: smoke-tests
smoke-tests: all
	./smoke/run.sh $(BUILDDIR)

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
meson_opts += $(MESON_EXTRA_OPTS)

$(BUILDDIR)/build.ninja:
	meson setup $(BUILDDIR) $(meson_opts)

c_src = git ls-files '*.[ch]' ':!:subprojects'
all_files = git ls-files ':!:subprojects'
licensed_files = git ls-files ':!:*.svg' ':!:LICENSE' ':!:README.md' ':!:subprojects'

.PHONY: lint
lint:
	@echo '[clang-format]'
	$Q tmp=`mktemp` && trap "rm -f $$tmp" EXIT && $(c_src) > "$$tmp" && \
		clang-format --files="$$tmp" --dry-run --Werror
	@echo '[license-check]'
	$Q ! $(licensed_files) | while read -r f; do \
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
	@echo '[white-space]'
	$Q $(all_files) | xargs devtools/check-whitespace

.PHONY: format
format:
	@echo '[clang-format]'
	$Q tmp=`mktemp` && trap "rm -f $$tmp" EXIT && $(c_src) > "$$tmp" && \
		clang-format --files="$$tmp" -i --verbose

REVISION_RANGE ?= origin/main..

.PHONY: check-patches
check-patches:
	$Q devtools/check-patches $(REVISION_RANGE)
