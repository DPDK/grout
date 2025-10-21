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

.PHONY: debug
debug: BUILDTYPE = debug
debug: SANITIZE = address
debug: all

.PHONY: unit-tests
unit-tests: $(BUILDDIR)/build.ninja
	$Q meson test -C $(BUILDDIR) --print-errorlogs $(if $(filter 1,$V),--verbose)

.PHONY: smoke-tests
smoke-tests: all
	./smoke/run.sh $(BUILDDIR)

.PHONY: update-graph
update-graph: all
	$Q set -xe; tmp=`mktemp -d`; \
	trap "kill %1; wait; rm -rf $$tmp" EXIT; \
	export GROUT_SOCK_PATH="$$tmp/sock"; \
	$(BUILDDIR)/grout -t & \
	socat FILE:/dev/null UNIX-CONNECT:$$GROUT_SOCK_PATH,retry=10 && \
	$(BUILDDIR)/grcli graph show brief | dot -Tsvg > docs/graph.svg

.PHONY: coverage
coverage:
	$Q mkdir -p $(BUILDDIR)/coverage
	$Q gcovr --html-details $(BUILDDIR)/coverage/index.html --txt \
		-e '.*_test.c' -e 'subprojects/*' --gcov-ignore-parse-errors \
		-ur . $(BUILDDIR)
	@echo Coverage data is present in $(BUILDDIR)/coverage/index.html

.PHONY: all
clean:
	$Q ninja -C $(BUILDDIR) clean $(ninja_opts)

.PHONY: install
install: $(BUILDDIR)/build.ninja
	$Q meson install -C $(BUILDDIR) --skip-subprojects

meson_opts = --buildtype=$(BUILDTYPE) --werror --warnlevel=2
meson_opts += -Db_sanitize=$(SANITIZE) -Ddpdk_static=true
meson_opts += $(MESON_EXTRA_OPTS)

$(BUILDDIR)/build.ninja:
	meson setup $(BUILDDIR) $(meson_opts)

empty :=
space := $(empty) $(empty)
version := $(shell { git describe --long --abbrev=8 --dirty 2>/dev/null || \
	sed -En 's/.* \|\| echo (v[0-9\.]+)\>.*/\1-'`date +%Y%m%d%H%M%S.local`'/p' meson.build; } | \
	sed 's/^v//;s/-/ /')
debversion = $(subst $(space),+,$(version))

.PHONY: deb
deb:
	$Q rm -f debian/changelog
	dch --create --package grout --newversion '$(debversion)' -M Development snapshot.
	dpkg-buildpackage -b
	$Q arch=`dpkg-architecture -qDEB_HOST_ARCH` && \
	mv -vf ../grout-dev_$(debversion)_all.deb grout-dev_all.deb && \
	mv -vf ../grout-prometheus_$(debversion)_all.deb grout-prometheus_all.deb && \
	mv -vf ../grout_$(debversion)_$$arch.deb grout_$$arch.deb && \
	mv -vf ../grout-dbgsym_$(debversion)_$$arch.deb grout-dbgsym_$$arch.deb && \
	mv -vf ../grout-frr_$(debversion)_$$arch.deb grout-frr_$$arch.deb && \
	mv -vf ../grout-frr-dbgsym_$(debversion)_$$arch.deb grout-frr-dbgsym_$$arch.deb

rpmversion = $(firstword $(version))
rpmrelease = $(subst -,.,$(lastword $(version))).$(shell sed -nE 's/PLATFORM_ID="platform:(.*)"/\1/p' /etc/os-release)

.PHONY: rpm
rpm:
	rpmbuild -bb --build-in-place -D 'version $(rpmversion)' -D 'release $(rpmrelease)' rpm/grout.spec
	$Q arch=`rpm --eval '%{_arch}'` && \
	version="$(rpmversion)-$(rpmrelease)" && \
	mv -vf ~/rpmbuild/RPMS/noarch/grout-devel-$$version.noarch.rpm grout-devel.noarch.rpm && \
	mv -vf ~/rpmbuild/RPMS/noarch/grout-prometheus-$$version.noarch.rpm grout-prometheus.noarch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-$$version.$$arch.rpm grout.$$arch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-debuginfo-$$version.$$arch.rpm grout-debuginfo.$$arch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-frr-$$version.$$arch.rpm grout-frr.$$arch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-frr-debuginfo-$$version.$$arch.rpm grout-frr-debuginfo.$$arch.rpm

CLANG_FORMAT ?= clang-format
c_src = git ls-files '*.[ch]' ':!:subprojects'
all_files = git ls-files ':!:subprojects'
licensed_files = git ls-files ':!:*.svg' ':!:licenses' ':!:*.md' ':!:*.asc' ':!:subprojects' ':!:debian' ':!:.*'

.PHONY: lint
lint:
	@echo '[clang-format]'
	$Q tmp=`mktemp` && trap "rm -f $$tmp" EXIT && $(c_src) > "$$tmp" && \
		$(CLANG_FORMAT) --files="$$tmp" --dry-run --Werror
	@echo '[license-check]'
	$Q ! $(licensed_files) | while read -r f; do \
		if echo "$$f" | grep -q '^frr/'; then \
			if ! grep -qF 'SPDX-License-Identifier: GPL-2.0-or-later' "$$f"; then \
				echo "$$f"; \
			fi; \
		else \
			if ! grep -qF 'SPDX-License-Identifier: BSD-3-Clause' $$f; then \
				echo $$f; \
			fi; \
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
	@echo '[comments]'
	$Q $(c_src) | xargs devtools/check-comments
	@echo '[codespell]'
	$Q codespell *

.PHONY: format
format:
	@echo '[clang-format]'
	$Q tmp=`mktemp` && trap "rm -f $$tmp" EXIT && $(c_src) > "$$tmp" && \
		$(CLANG_FORMAT) --files="$$tmp" -i --verbose

REVISION_RANGE ?= @{u}..

.PHONY: check-patches
check-patches:
	$Q devtools/check-patches $(REVISION_RANGE)

.PHONY: git-config
git-config:
	git config format.subjectPrefix "PATCH grout"
	git config sendemail.to "grout@dpdk.org"
	git config format.notes true
	git config format.coverFromDescription subject
	git config notes.rewriteRef refs/notes/commits
	git config notes.rewriteMode concatenate
	@mkdir -p .git/hooks
	@rm -f .git/hooks/commit-msg*
	ln -s ../../devtools/commit-msg .git/hooks/commit-msg

.PHONY: tag-release
tag-release:
	@cur_version=`sed -En 's/.* \|\| echo v([0-9\.]+)\>.*$$/\1/p' meson.build` && \
	next_version=`echo $$cur_version | awk -F. -v OFS=. '{$$(NF) += 1; print}'` && \
	read -rp "next version ($$next_version)? " n && \
	if [ -n "$$n" ]; then next_version="$$n"; fi && \
	set -xe && \
	sed -i "s/\<v$$cur_version\>/v$$next_version/" meson.build && \
	git commit -sm "grout: release v$$next_version" -m "`devtools/git-stats v$$cur_version..`" meson.build && \
	git tag -sm "`devtools/git-stats v$$cur_version..HEAD^`" "v$$next_version"
