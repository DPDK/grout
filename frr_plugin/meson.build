# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Maxime Leroy, Free Mobile

if not get_option('frr').enabled()
  if get_option('frr_install').enabled()
    error('Option `frr_install` requires `frr=true`')
  endif
  subdir_done()
endif

frr_install_opt = get_option('frr_install')
frr_install_str = frr_install_opt.enabled() ? 'enabled' : 'disabled'

frr = subproject('frr', default_options: ['frr_install=' + frr_install_str])
frr_dep = dependency('frr', version: '>= 10.3', fallback: ['frr', 'frr_dep'])
moduledir =  frr_dep.get_variable('moduledir')

frr_plugin_src = files(
  'zebra_dplane_grout.c',
  'rt_grout.c',
  'if_grout.c',
)

frr_plugin = shared_module(
  'frr_dplane_grout',
  frr_plugin_src,
  name_prefix: '',
  dependencies: [frr_dep],
  include_directories: api_inc + include_directories('.'),
  install: true,
  override_options: [ 'c_std=gnu11' ],
  c_args : [
    '-DHAVE_CONFIG_H',
    '-D_GNU_SOURCE',
    '-fms-extensions',
    '-Wno-missing-field-initializers',
    '-Wno-implicit-fallthrough',
    '-Wno-unused-parameter',
  ],
)

frr_install_opt = get_option('frr_install')
plugin_path = frr_plugin.full_path()
plugin_dest = moduledir + '/frr_dplane_grout.so'
frr_prefix = frr_dep.get_variable('frr_prefix')
frr_daemons_file = frr_prefix / 'etc/frr/daemons'
script = meson.current_source_dir() / 'frr_plugin_install.sh'
plugin_stamp = '.install-stamp'

if frr_install_opt.enabled()
  plugin_install_cmd = [
    script,               # helper script
    plugin_path,          # $1 – built .so
    plugin_dest,          # $2 – install location
    frr_daemons_file,     # $3 – daemons file to patch
    '@OUTPUT@',           # $4 – stamp file
  ]
else
  # do nothing, just create the stamp so Meson is happy
  plugin_install_cmd = ['/usr/bin/true', '&&', 'touch', '@OUTPUT@']
endif

install_plugin = custom_target(
  'install_frr_dplane_grout',
  output  : plugin_stamp,
  command : plugin_install_cmd,
  depends : [frr_plugin],
  build_by_default: true,
)

alias_target('frr_plugin_install', install_plugin)
