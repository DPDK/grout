# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

client_sources += files(
  'port.c',
)
client_sources += custom_target(
  command: cmdline_gen,
  input: files('port.list'),
  output: 'infra_port.h'
)
