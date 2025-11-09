# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

cli_src += files(
  'complete.c',
  'ec_node_devargs.c',
  'ec_node_dyn.c',
  'ecoli.c',
  'exec.c',
  'interact.c',
  'log.c',
  'main.c',
  'man_commands.c',
  'man_main.c',
  'quit.c',
)

if not compiler.has_function(
  'scols_line_sprintf',
  prefix: '#include <libsmartcols.h>',
  dependencies: [smartcols_dep],
)
  cli_src += files('table.c')
  cli_cflags += ['-DNEED_SCOLS_LINE_SPRINTF']
endif

cli_inc += include_directories('.')

install_data(
  files('grcli.bash-completion'),
  rename: ['grcli'],
  install_dir: get_option('datadir') / 'bash-completion/completions',
)
