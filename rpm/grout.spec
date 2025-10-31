# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

%undefine _debugsource_packages
%global _lto_cflags %nil
%global branch main
%global __meson_wrap_mode default

Name: grout
Summary: Graph router based on DPDK
Group: System Environment/Daemons
URL: https://github.com/DPDK/grout
License: BSD-3-Clause AND GPL-2.0-or-later
Version: %{version}
Release: %{release}
Source0: https://github.com/DPDK/grout/archive/%{branch}.tar.gz#/%{name}-%{version}-%{release}.tar.gz

BuildRequires: gcc
BuildRequires: git
BuildRequires: golang-github-cpuguy83-md2man
BuildRequires: libarchive-devel
BuildRequires: libcmocka-devel
BuildRequires: libedit-devel
BuildRequires: libevent-devel
BuildRequires: libsmartcols-devel
BuildRequires: make
BuildRequires: meson
BuildRequires: ninja-build
BuildRequires: numactl-devel
BuildRequires: pkgconf
BuildRequires: python3-pyelftools
BuildRequires: rdma-core-devel
BuildRequires: systemd

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

%if %{undefined fedora}
%debug_package
%endif

%package devel
Summary: Development headers for building %{name} API clients
BuildArch: noarch
Suggests: %{name}

%description devel
This package contains the development headers to build %{grout} API clients.

%package prometheus
Summary: Prometheus exporter for DPDK/grout
BuildArch: noarch
Requires: python3

%description prometheus
Prometheus exporter for grout.

%package frr
Summary: FRR dplane plugin for grout
Requires: frr = %(sed -n "s/revision = frr-//p" subprojects/frr.wrap)

%description frr
FRR dplane plugin for grout

%build
%meson -Ddpdk:platform=generic -Dfrr=enabled -Ddpdk_static=true
%meson_build

%install
%meson_install --skip-subprojects

install -D -m 0755 subprojects/dpdk/usertools/dpdk-telemetry-exporter.py %{buildroot}%{_bindir}/grout-telemetry-exporter
install -D -m 0644 -t %{buildroot}%{_datadir}/dpdk/telemetry-endpoints subprojects/dpdk/usertools/telemetry-endpoints/*

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%files
%doc README.md
%license licenses/BSD-3-clause.txt
%config %{_sysconfdir}/default/grout
%config %{_sysconfdir}/grout.init
%attr(644, root, root) %{_unitdir}/grout.service
%attr(644, root, root) %{_datadir}/bash-completion/completions/grout
%attr(644, root, root) %{_datadir}/bash-completion/completions/grcli
%attr(755, root, root) %{_bindir}/grcli
%attr(755, root, root) %{_bindir}/grout
%attr(644, root, root) %{_mandir}/man1/grcli*.1*
%attr(644, root, root) %{_mandir}/man8/grout.8*

%files devel
%doc README.md
%license licenses/BSD-3-clause.txt
%{_includedir}/gr_*.h

%files prometheus
%doc README.md
%license licenses/BSD-3-clause.txt
%attr(755, root, root) %{_bindir}/grout-telemetry-exporter
%attr(644, root, root) %{_datadir}/dpdk/telemetry-endpoints/*

%files frr
%doc README.md
%license licenses/GPL-2.0-or-later.txt
%attr(755, root, root) %{_libdir}/frr/modules/dplane_grout.so
%attr(644, root, root) %{_mandir}/man7/grout-frr.7*

%changelog
* Mon Sep 02 2024 Robin Jarry <rjarry@redhat.com>
- Nightly build
