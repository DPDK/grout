# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

%undefine _debugsource_packages
%global _lto_cflags %nil
%global branch main
%global __meson_wrap_mode default
%if %{defined toolset}
%global __meson /usr/bin/scl run %toolset -- /usr/bin/meson
%endif

Name: grout
Summary: Graph router based on DPDK
Group: System Environment/Daemons
URL: https://github.com/DPDK/grout
License: BSD-3-Clause
Version: %{version}
Release: %{release}
Source0: https://github.com/DPDK/grout/archive/%{branch}.tar.gz#/%{name}-%{version}-%{release}.tar.gz

%if %{undefined toolset}
BuildRequires: gcc >= 13
%else
BuildRequires: %toolset
BuildRequires: scl-utils
%endif
BuildRequires: git
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
BuildRequires: golang-github-cpuguy83-md2man
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

%build
%meson -Ddpdk:platform=generic -Dfrr=disabled
%meson_build

%install
%meson_install --skip-subprojects

install -D -m 0644 main/grout.default %{buildroot}%{_sysconfdir}/default/grout
install -D -m 0644 main/grout.init %{buildroot}%{_sysconfdir}/grout.init
install -D -m 0644 main/grout.service %{buildroot}%{_unitdir}/grout.service
install -D -m 0644 main/grout.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/grout
install -D -m 0644 cli/grcli.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/grcli

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
%attr(644, root, root) %{_mandir}/man1/grcli.1*
%attr(644, root, root) %{_mandir}/man7/grout-frr.7*
%attr(644, root, root) %{_mandir}/man8/grout.8*

%files devel
%doc README.md
%license licenses/BSD-3-clause.txt
%{_includedir}/gr_*.h

%changelog
* Mon Sep 02 2024 Robin Jarry <rjarry@redhat.com>
- Nightly build
