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

files = `find * -path $(builddir) -prune -o -type f -name $1 -print`
c_src = $(call files,'*.[ch]')
py_src = $(call files,'*.py')
empty =
space = $(empty) $(empty)
cli_dirs = $(builddir)/cli cli $(wildcard modules/*/cli)
PYTHONPATH = $(subst $(space),:,$(cli_dirs))

.PHONY: lint
lint: $(builddir)/build.ninja
	clang-format --dry-run --Werror $(c_src)
	black --diff --check $(py_src)
	isort --diff --check-only $(py_src)
	ninja -C $(builddir) cffi_ext
	PYTHONPATH=$(PYTHONPATH) pylint $(py_src)

.PHONY: format
format:
	clang-format -i --verbose $(c_src)
	isort $(py_src)
	black $(py_src)
