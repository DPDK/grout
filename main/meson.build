# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

src += files(
  'api.c',
  'dpdk.c',
  'event.c',
  'main.c',
  'metrics.c',
  'module.c',
  'sd_notify.c',
  'signals.c',
  'sort.c',
  'unix.c'
)

inc += include_directories('.')

tests += [
  {
    'sources': files('vec_test.c'),
    'link_args': [],
  },
  {
    'sources': files('id_pool_test.c'),
    'link_args': [
      '-Wl,--wrap=rte_free',
      '-Wl,--wrap=rte_malloc',
    ],
  },
]

systemd_dep = dependency('systemd', required: false)
if systemd_dep.found()
  systemd_system_unit_dir = systemd_dep.get_variable(
    pkgconfig: 'systemdsystemunitdir',
    pkgconfig_define: ['prefix', get_option('prefix')]
  )
  install_data(
    files('grout.service'),
    install_dir: systemd_system_unit_dir,
  )
  install_data(
    files('grout.default'),
    rename: ['grout'],
    install_dir: get_option('sysconfdir') / 'default',
  )
  install_data('grout.init', install_dir: get_option('sysconfdir'))
endif

install_data(
  files('grout.bash-completion'),
  rename: ['grout'],
  install_dir: get_option('datadir') / 'bash-completion/completions',
)
