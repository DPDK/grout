# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile
project('frr', 'c',
  version: run_command('sed', '-nE',
    's/.*AC_INIT.*\[([0-9]+\.[0-9]+\.[0-9]+)(-dev)?\].*/\\1/p',
    meson.current_source_dir() / 'configure.ac',
    capture: true,
    check:true).stdout().strip(),
  license: 'GPL-2.0-or-later',
  meson_version: '>= 0.63.0')

srcdir = meson.current_source_dir()
builddir = meson.current_build_dir()
libdir = builddir / 'lib' / '.libs'
prefix = meson.global_build_root()  / 'frr_install'

# make sure the out-of-tree build directory exists
run_command('mkdir', '-p', builddir, check: true)

bootstrap = custom_target(
  'bootstrap',
  output: '.bootstrap-stamp',
  command: [
    'sh', '-c',
    'autoreconf -is -Wall,no-override "' + srcdir + '" && touch "@OUTPUT@"'
  ],
)
alias_target('bootstrap', bootstrap)

configure_stamp = '.configure-stamp'
moduledir = prefix / get_option('libdir') / 'frr/modules'

user_name  = run_command('id', '-un', check: true).stdout().strip()
group_name = run_command('id', '-gn', check: true).stdout().strip()
extra_configure_option = '--enable-user=' + user_name + ' ' + '--enable-group=' + group_name

buildtype = get_option('buildtype')
debug = buildtype.startswith('debug')
if debug
  extra_configure_option += ' --enable-dev-build'
endif

configure = custom_target(
  'configure',
  output: configure_stamp,
  command: [
    'sh', '-c',
    'cd "' + builddir + '" && ' +
    '"' + srcdir + '/configure" ' +
    '--prefix="' + prefix + '" ' +
    '--with-moduledir="' + moduledir + '" ' +
    '--disable-doc --enable-multipath=256 ' +
    '--disable-ripd --disable-ripngd ' +
    '--disable-ldpd --disable-nhrpd --disable-eigrpd --disable-babeld  ' +
    '--disable-pimd --disable-pim6d --disable-pbrd --disable-fabricd ' +
    '--disable-vrrpd --disable-pathd --disable-ospfapi --disable-ospfclient ' +
    '--disable-python-runtime ' + extra_configure_option + ' ' +
    '&&  touch "' + configure_stamp + '"'
  ],
  depends: bootstrap,
)
alias_target('configure', configure)

build_stamp = '.build-stamp'
install_cmd = 'make install && sh -x ' + srcdir + '/frr_install.sh ' + srcdir + ' ' + prefix + ' && '
build_cmd = 'cd "' + builddir + '" && make -j && ' + install_cmd + 'touch "' + build_stamp + '"'

build = custom_target(
  'build',
  output: build_stamp,
  command: [ 'sh', '-c', build_cmd ],
  depends: configure,
  build_by_default: true,
)
alias_target('build', build)

frr_dep = declare_dependency(
  include_directories: include_directories('.', 'lib'),
  compile_args: [
    '-fms-extensions',
    '-DMULTIPATH_NUM=256',
    '-Wno-missing-field-initializers',
    '-Wno-unused-parameter',
  ],
  sources: [build],
  version: meson.project_version(),
  variables: {
    'moduledir': moduledir,
    'prefix': prefix,
    'install_on_build': 'true',
  }
)
