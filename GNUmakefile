# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

BUILDDIR ?= build
BUILDTYPE ?= debugoptimized
SANITIZE ?= none
COVERAGE ?= false
FRR ?= $(shell sed -En "s/.*'frr_version'.*value: '([^']+)'.*/\\1/p" meson_options.txt)
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
debug: COVERAGE = true
debug: all

.PHONY: unit-tests
unit-tests: $(BUILDDIR)/build.ninja
	$Q meson test -C $(BUILDDIR) --print-errorlogs $(if $(filter 1,$V),--verbose)

smoke_scripts := $(sort $(wildcard smoke/*_test.sh))
smoke_frr := $(filter %_frr_test.sh,$(smoke_scripts))
test_frr := $(shell jq -e '.[] | select(.name == "frr" and .value == "enabled")' \
	$(BUILDDIR)/meson-info/intro-buildoptions.json >/dev/null 2>&1 && echo yes)
ifneq ($(test_frr),yes)
smoke_scripts := $(filter-out $(smoke_frr),$(smoke_scripts))
endif
ifneq ($(SMOKE_MATCH),)
smoke_match := $(foreach m,$(SMOKE_MATCH),$(wildcard smoke/*$(m)*))
smoke_scripts := $(filter $(smoke_match),$(smoke_scripts))
endif
ifneq ($(SMOKE_SKIP),)
smoke_skip := $(foreach s,$(SMOKE_SKIP),$(wildcard smoke/*$(s)*))
smoke_scripts := $(filter-out $(smoke_skip),$(smoke_scripts))
endif
PAUSE_ON_FAILURE ?= false
INTERACTIVE ?= false
GDB ?= false
smoke_env := PAUSE_ON_FAILURE=$(PAUSE_ON_FAILURE)
smoke_env += INTERACTIVE=$(INTERACTIVE)
smoke_env += GDB=$(GDB)

.PHONY: smoke-tests smoke smoke/
smoke-tests smoke smoke/: $(smoke_scripts)

.PHONY: smoke_env_print
smoke_env_print:
	@echo $(smoke_env)

.PHONY: $(smoke_scripts)
$(smoke_scripts): | smoke_env_print
	$Q log=$$(mktemp); \
	trap "rm -f $$log" EXIT; \
	printf '%s\n' $@; \
	if ! sudo $(smoke_env) $@ $(BUILDDIR) </dev/null >"$$log" 2>&1; then \
		printf '%s\n' '==================================================='; \
		printf '+ %s\n' $@; \
		cat "$$log"; \
		printf '%s\n' '---------------------------------------------------'; \
		printf '%s ... FAILED\n' $@; \
		printf '%s\n' '---------------------------------------------------'; \
		false; \
	fi

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
		-e '.*_test.c' -e 'subprojects/.*' --gcov-ignore-parse-errors \
		--gcov-executable `$(CC) -print-prog-name=gcov` \
		--object-directory $(BUILDDIR) \
		--sort uncovered-percent \
		-r . $(BUILDDIR)
	@echo Coverage data is present in $(BUILDDIR)/coverage/index.html

.PHONY: all
clean:
	$Q ninja -C $(BUILDDIR) clean $(ninja_opts)

.PHONY: install
install: $(BUILDDIR)/build.ninja
	$Q meson install -C $(BUILDDIR) --skip-subprojects

meson_opts = --buildtype=$(BUILDTYPE) --werror --warnlevel=2
meson_opts += -Db_sanitize=$(SANITIZE) -Db_coverage=$(COVERAGE)
meson_opts += -Dfrr_version=$(FRR)
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
	GROUT_VERSION='$(debversion)' dpkg-buildpackage -b
	$Q arch=`dpkg-architecture -qDEB_HOST_ARCH` && \
	mv -vf ../grout-headers_$(debversion)_all.deb grout-headers_all.deb && \
	mv -vf ../grout_$(debversion)_$$arch.deb grout_$$arch.deb && \
	mv -vf ../grout-dbgsym_$(debversion)_$$arch.deb grout-dbgsym_$$arch.deb

rpmversion = $(firstword $(version))
rpmdist = $(shell rpm --eval %{dist} 2>/dev/null)
rpmrelease = $(subst -,.,$(lastword $(version)))$(rpmdist)
rpmbuild_opts = $(addprefix --with=,$(WITH)) $(addprefix --without=,$(WITHOUT))

.PHONY: rpm
rpm:
	GROUT_VERSION="$(rpmversion)-$(rpmrelease)" rpmbuild -bb --build-in-place $(rpmbuild_opts) \
		-D 'version $(rpmversion)' -D 'release $(rpmrelease)' rpm/grout.spec
	$Q arch=`rpm --eval '%{_arch}'` && \
	version="$(rpmversion)-$(rpmrelease)" && \
	mv -vf ~/rpmbuild/RPMS/noarch/grout-headers-$$version.noarch.rpm grout-headers.noarch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-$$version.$$arch.rpm grout.$$arch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/grout-debuginfo-$$version.$$arch.rpm grout-debuginfo.$$arch.rpm && \
	if ! echo "$(WITHOUT)" | grep -qw frr; then \
		mv -vf ~/rpmbuild/RPMS/$$arch/grout-frr-$$version.$$arch.rpm grout-frr.$$arch.rpm && \
		mv -vf ~/rpmbuild/RPMS/$$arch/grout-frr-debuginfo-$$version.$$arch.rpm grout-frr-debuginfo.$$arch.rpm; \
	fi

frr_version = $(shell sed -nE 's/^source_filename = frr-(.+)\.tar\.gz$$/\1/p' subprojects/frr-$(FRR).wrap)
frr_hash = $(shell sed -nE 's/^source_hash = //p' subprojects/frr-$(FRR).wrap)
frr_archive = subprojects/packagecache/frr-$(frr_version).tar.gz

.PHONY: frr-rpm
frr-rpm:
	meson subprojects download frr-$(FRR)
	echo '$(frr_hash)  $(frr_archive)' | sha256sum -c
	install -Dt ~/rpmbuild/SOURCES $(frr_archive)
	rpmbuild -bb -D'version $(frr_version)' -D 'release 1$(rpmdist).grout' rpm/frr.spec
	$Q arch=`rpm --eval '%{_arch}'` && \
	version="$(frr_version)-1$(rpmdist).grout" && \
	mv -vf ~/rpmbuild/RPMS/noarch/frr-headers-$$version.noarch.rpm frr-headers.noarch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/frr-$$version.$$arch.rpm frr.$$arch.rpm && \
	mv -vf ~/rpmbuild/RPMS/$$arch/frr-debuginfo-$$version.$$arch.rpm frr-debuginfo.$$arch.rpm

CLANG_FORMAT ?= clang-format
c_src = git ls-files '*.[ch]' ':!:subprojects'
all_files = git ls-files ':!:subprojects'
licensed_files = git ls-files ':!:*.svg' ':!:licenses' ':!:*.md' ':!:*.asc' ':!:subprojects' ':!:debian' ':!:.*' ':!:*.scdoc' ':!:*.json'

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
	$Q $(c_src) '*.sh' meson.build GNUmakefile | xargs devtools/check-comments
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
