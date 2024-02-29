# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

builddir = build
ifeq ($V,1)
ninja_opts = --verbose
endif

.PHONY: all
all: $(builddir)/build.ninja
	ninja -C $(builddir) $(ninja_opts)

.PHONY: all
clean:
	ninja -C $(builddir) clean $(ninja_opts)

.PHONY: install
install: $(builddir)/build.ninja
	ninja -C $(builddir) install $(ninja_opts)

$(builddir)/build.ninja:
	meson setup $(builddir)

prune = -path $1 -prune -o
exclude = $(builddir) subprojects LICENSE .git README.md main/include/stb_ds.h
c_src = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -name '*.[ch]' -print`
all_files = `find * .* $(foreach d,$(exclude),$(call prune,$d)) -type f -print`

.PHONY: lint
lint: $(builddir)/build.ninja
	@echo '[clang-format]'
	@clang-format --dry-run --Werror $(c_src)
	@echo '[license-check]'
	@! for f in $(all_files); do \
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
	@clang-format -i --verbose $(c_src)
