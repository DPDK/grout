# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Maxime Leroy, Free Mobile
frr_opt = get_option('frr')

if frr_opt.disabled()
  subdir_done()
endif

frr_dep = dependency('frr', version: '>= 10.5', required: false)
if not frr_dep.found()
  if get_option('frr').enabled()
    sp = subproject('frr')
    frr_dep = sp.get_variable('frr_dep')
  else
    subdir_done()
  endif
endif

install_build_flag = frr_dep.get_variable('install_on_build', default_value: 'false') == 'true'
frr_plugin = shared_module(
  'dplane_grout',
  files(
    'if_grout.c',
    'if_map.c',
    'rt_grout.c',
    'zebra_dplane_grout.c',
  ),
  name_prefix: '',
  dependencies: [frr_dep],
  include_directories: api_inc + include_directories('.'),
  install: not install_build_flag,
  install_dir: frr_dep.get_variable('moduledir'),
  override_options: ['b_sanitize=none'],
)

if install_build_flag
  install_plugin = custom_target(
    'install_frr_dplane_grout',
    output: '.install-stamp',
    command: ['install', '-Dt', frr_dep.get_variable('moduledir'), frr_plugin],
    depends: [frr_plugin],
    build_by_default: true,
  )

  alias_target('frr_plugin_install', install_plugin)
endif
