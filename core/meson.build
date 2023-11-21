# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

sources += files(
  'control.c',
  'dpdk.c',
  'main.c',
  'signals.c',
)

api = custom_target(
  command: proto_gen,
  input: files('br_api.proto'),
  output: proto_output,
)

sources += api
sources += files('api.c')
client_sources += api
client_sources += files('api.c')

api_headers += files('br_api.h', 'br_api.proto')

include_dirs += include_directories('.')
