# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

api = custom_target(
  command: proto_gen,
  input: files('platform.proto'),
  output: proto_output,
)

sources += files(
  'control.c',
)
sources += api
api_headers += files('bro_platform.h')

client_sources += files(
  'cli.c',
)
client_sources += custom_target(
  command: cmdline_gen,
  input: files('cli.list'),
  output: 'platform_cli.h'
)
client_sources += api

client_include_dirs += include_directories('.')
