# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

cli_src += files(
  'complete.c',
  'display.c',
  'dump.c',
  'ec_node_devargs.c',
  'ec_node_dyn.c',
  'ecoli.c',
  'exec.c',
  'interact.c',
  'main.c',
  'pager.c',
  'quit.c',
  'tty.c',
)

cli_inc += include_directories('.')

install_data(
  files('grcli.bash-completion'),
  rename: ['grcli'],
  install_dir: get_option('datadir') / 'bash-completion/completions',
)
