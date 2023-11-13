# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

sources += files(
  'control.c',
)
api_headers += files('include/bro_platform.h')
include_dirs += include_directories('include')

client_sources += files(
  'cli.c',
)
client_sources += custom_target(
  command: cmdline_gen,
  input: files('cli.list'),
  output: 'cli.h'
)
