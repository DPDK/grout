# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

%global _lto_cflags %nil
%global branch main
%global __meson_wrap_mode default
%{!?_unitdir:%define _unitdir /usr/lib/systemd/system}

Name: grout
Summary: Graph router based on DPDK
Group: System Environment/Daemons
URL: https://github.com/rjarry/grout
License: BSD-3-Clause
Version: %{version}
Release: %{release}
Source0: https://github.com/rjarry/grout/archive/%{branch}.tar.gz#/%{name}-%{version}-%{release}.tar.gz

BuildRequires: git gcc make meson ninja-build pkgconf scdoc
BuildRequires: libcmocka-devel libedit-devel libevent-devel libsmartcols-devel
BuildRequires: python3-pyelftools numactl-devel

%description
grout stands for Graph Router. In English, "grout" refers to thin mortar that
hardens to fill gaps between tiles.

grout is a DPDK based network processing application. It uses the rte_graph
library for data path processing.

Its main purpose is to simulate a network function or a physical router for
testing/replicating real (usually closed source) VNF/CNF behavior with an
opensource tool.

It comes with a client library to configure it over a standard UNIX socket and
a CLI that uses that library. The CLI can be used as an interactive shell, but
also in scripts one command at a time, or by batches.

%debug_package

%build
%meson --buildtype=debugoptimized -Ddpdk:platform=generic
%meson_build

%install
rm -rf %{buildroot}
%meson_install --skip-subprojects

install -D -m 0644 main/grout.default %{buildroot}%{_sysconfdir}/default/grout
install -D -m 0644 main/grout.init %{buildroot}%{_sysconfdir}/grout.init
install -D -m 0644 main/grout.service %{buildroot}%{_unitdir}/grout.service
install -D -m 0644 main/grout.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/grout
install -D -m 0644 cli/grcli.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/grcli

%clean
rm -rf %{buildroot} %{_vpath_builddir}

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%files
%{_sysconfdir}/default/grout
%{_sysconfdir}/grout.init
%{_unitdir}/grout.service
%{_datadir}/bash-completion/completions/grout
%{_datadir}/bash-completion/completions/grcli
%{_bindir}/grcli
%{_sbindir}/grout
%{_mandir}/man1/grcli.1*
%{_mandir}/man8/grout.8*

%changelog
* Mon Sep 02 2024 Robin Jarry <rjarry@redhat.com>
- Nightly build