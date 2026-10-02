# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Maxime Leroy, Free Mobile

frr_opt = get_option('frr')
frr_version = get_option('frr_version')

if frr_opt.disabled()
  subdir_done()
endif

frr_dep = dependency(
  'frr',
  version: '>= 10.5',
  required: frr_opt,
  fallback: ['frr-' + frr_version, 'frr_dep'],
)

if not frr_dep.found()
  subdir_done()
endif

install_build_flag = frr_dep.get_variable('install_on_build', default_value: 'false') == 'true'
frr_moduledir = frr_dep.get_variable('moduledir')

frr_version = frr_dep.version()
frr_ver = frr_version.split('.')
# Match MAKE_FRRVERSION() layout from libfrr.h: MAJOR(8) | MINOR(16) | SUB(8)
frr_ver_num = frr_ver[0].to_int() * 16777216 + frr_ver[1].to_int() * 256 + frr_ver[2].to_int()
frr_c_args = [
  '-DCURRENT_FRR_VERSION=' + frr_ver_num.to_string(),
  '-Wno-constant-logical-operand',
]

frr_plugin = shared_module(
  'dplane_grout',
  files(
    'if_grout.c',
    'if_map.c',
    'l3vni_map.c',
    'rt_grout.c',
    'zebra_dplane_grout.c',
  ) + grout_header,
  name_prefix: '',
  c_args: frr_c_args,
  dependencies: [frr_dep],
  include_directories: api_inc + include_directories('.'),
  install: not install_build_flag,
  install_dir: frr_moduledir,
  override_options: ['b_sanitize=none'],
)

if install_build_flag
  install_plugin = custom_target(
    'install_frr_dplane_grout',
    output: '.install-stamp',
    depends: [frr_plugin],
    build_by_default: true,
    command: [
      'sh', '-c', 'install -Dt $1 $2 && touch $3', '--', frr_moduledir, frr_plugin, '@OUTPUT@',
    ],
  )
endif

if cmocka_dep.found()
  # FRR is built as an external subproject and only provides include dirs
  # (the dplane_grout plugin inherits FRR symbols from the parent process at
  # runtime). For a standalone test binary we must link libfrr explicitly.
  frr_prefix = frr_dep.get_variable('prefix')
  frr_libdir = frr_prefix / 'lib'
  mpls_frr_test_exe = executable(
    'mpls_frr_test',
    files('mpls_frr_test.c', 'rt_grout.c') + grout_header,
    c_args: frr_c_args + ['-D__GROUT_UNIT_TEST__'],
    include_directories: api_inc + include_directories('.'),
    dependencies: [frr_dep, cmocka_dep],
    link_args: ['-L' + frr_libdir, '-lfrr', '-Wl,-rpath,' + frr_libdir],
    install: false,
    override_options: ['b_sanitize=none'],
  )
  test('mpls_frr_test', mpls_frr_test_exe, suite: 'unit')
endif

systemd_dep = dependency('systemd', required: false)
if systemd_dep.found()
  systemd_system_unit_dir = systemd_dep.get_variable(
    pkgconfig: 'systemdsystemunitdir',
    pkgconfig_define: ['prefix', get_option('prefix')]
  )
  install_data(
    files('grout.conf'),
    install_dir: systemd_system_unit_dir / 'frr.service.d',
  )
endif
