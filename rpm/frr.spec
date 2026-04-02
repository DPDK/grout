# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

%global frr_libdir %{_libexecdir}/frr

%global _hardened_build 1
%global selinuxtype targeted
%define _legacy_common_support 1

Name: frr
Version: %{version}
Release: 1%{?dist}.grout
Summary: Routing daemon
License: GPL-2.0-or-later AND ISC AND LGPL-2.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND (GPL-2.0-or-later  OR ISC) AND MIT
URL: http://www.frrouting.org
Source0: %{name}-%{version}.tar.gz

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: bison >= 2.7
BuildRequires: flex
BuildRequires: gcc
BuildRequires: groff
BuildRequires: json-c-devel
BuildRequires: libcap-devel
BuildRequires: libtool
BuildRequires: libxcrypt-devel
BuildRequires: libyang-devel >= 2.1.128
BuildRequires: make
BuildRequires: ncurses
BuildRequires: ncurses-devel
BuildRequires: pam-devel
BuildRequires: patch
BuildRequires: pcre2-devel
BuildRequires: protobuf-c-compiler
BuildRequires: protobuf-c-devel
BuildRequires: python3-devel
BuildRequires: readline-devel
BuildRequires: systemd-devel
BuildRequires: systemd-rpm-macros

Requires(pre): systemd
Requires(post): systemd
Requires(postun): systemd
Requires(preun): systemd

Obsoletes: quagga < 1.2.4-17
Provides: routingdaemon = %{version}-%{release}

%description
FRRouting is free software that manages TCP/IP based routing protocols. It takes
a multi-server and multi-threaded approach to resolve the current complexity
of the Internet.

FRRouting supports BGP4, OSPFv2, OSPFv3, ISIS, RIP, RIPng, PIM, NHRP, PBR,
EIGRP and BFD.

FRRouting is a fork of Quagga.

%package headers
Summary: Build headers for FRR
BuildArch: noarch
Requires: json-c-devel
Requires: libyang-devel

%description headers
Build headers for FRR required to generate out of tree dplane plugins

%prep
%autosetup -n %{name}-%{name}-%{version}

%build
export CFLAGS="%{optflags} -DINET_NTOP_NO_OVERRIDE"
autoreconf -ivf

%configure \
	--sbindir=%{frr_libdir} \
	--libdir=%{_libdir}/frr \
	--libexecdir=%{_libexecdir}/frr \
	--runstatedir=%{_rundir} \
	--with-crypto=openssl \
	--with-moduledir=%{_libdir}/frr/modules \
	--with-pkgconfigdir=%{_datadir}/pkgconfig \
	--with-vtysh-pager=less \
	--with-yangmodelsdir=%{_datadir}/frr-yang/ \
	--disable-babeld \
	--disable-doc \
	--disable-nhrpd \
	--disable-pathd \
	--disable-pbrd \
	--enable-multipath=64 \
	--enable-pcre2posix \
	--enable-user=frr \
	--enable-group=frr \
	--enable-vty-group=frr

%make_build PYTHON=%{__python3}

%install
%make_install

# Remove this file, as it is uninstalled and causes errors when building on RH9
rm -rf %{buildroot}%{_infodir}/dir

install -Dpm 644 tools/etc/frr/daemons %{buildroot}%{_sysconfdir}/frr/daemons
install -Dpm 644 tools/frr.service %{buildroot}%{_unitdir}/frr.service
install -Dpm 755 tools/frrinit.sh %{buildroot}%{frr_libdir}/frr
install -Dpm 755 tools/frrcommon.sh %{buildroot}%{frr_libdir}/frrcommon.sh
install -Dpm 755 tools/watchfrr.sh %{buildroot}%{frr_libdir}/watchfrr.sh
install -Dpm 644 redhat/frr.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/frr
install -Dpm 644 redhat/frr.pam %{buildroot}%{_sysconfdir}/pam.d/frr
install -dm 775 %{buildroot}/run/frr
install -dm 775 %{buildroot}/var/log/frr
install -dm 775 %{buildroot}/var/lib/frr
install -dm 755 %{buildroot}%{_tmpfilesdir}
install -dm 755 %{buildroot}%{_sysusersdir}

cat > %{buildroot}%{_sysusersdir}/%{name}.conf <<EOF
u frr - "FRRouting routing suite" /var/run/frr /sbin/nologin
EOF
cat > %{buildroot}%{_tmpfilesdir}/%{name}.conf <<EOF
d /run/frr 0755 frr frr -
d /var/log/frr 0755 frr frr -
d /var/lib/frr 0755 frr frr -
EOF

touch %{buildroot}%{_sysconfdir}/frr/frr.conf
touch %{buildroot}%{_sysconfdir}/frr/vtysh.conf

# Delete libtool archives
find %{buildroot} -type f -name "*.la" -delete -print
find %{buildroot} -type f -name "*.a" -delete -print

# Upstream does not maintain a stable API
rm %{buildroot}%{_libdir}/frr/*.so

%pre
systemd-sysusers - <<EOF
u frr - "FRRouting routing suite" /run/frr /sbin/nologin
EOF

%post
%systemd_post frr.service

%postun
%systemd_postun_with_restart frr.service

%preun
%systemd_preun frr.service

%files
%license COPYING
%dir %attr(750,frr,frr) %{_sysconfdir}/frr
%dir %attr(755,frr,frr) /run/frr
%dir %attr(755,frr,frr) /var/log/frr
%dir %attr(755,frr,frr) /var/lib/frr
%dir %{frr_libdir}/
%{frr_libdir}/*
%{_bindir}/mtracebis
%{_bindir}/vtysh
%dir %{_libdir}/frr
%{_libdir}/frr/*.so.*
%dir %{_libdir}/frr/modules
%{_libdir}/frr/modules/*
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/logrotate.d/frr
%config(noreplace) %attr(644,frr,frr) %{_sysconfdir}/frr/daemons
%config(noreplace) %attr(644,frr,frr) %{_sysconfdir}/frr/frr.conf
%config(noreplace) %attr(644,frr,frr) %{_sysconfdir}/frr/vtysh.conf
%config(noreplace) %{_sysconfdir}/pam.d/frr
%{_unitdir}/*.service
%dir %{_datadir}/frr-yang
%{_datadir}/frr-yang/*.yang
%{_sysusersdir}/%{name}.conf
%{_tmpfilesdir}/%{name}.conf

%files headers
%dir %{_includedir}/frr/
%{_includedir}/frr/*
%{_datadir}/pkgconfig/frr.pc

%changelog
* Thu Apr 02 2026 Robin Jarry <rjarry@redhat.com>
- Version shipped with grout
