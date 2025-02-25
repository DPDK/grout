# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

api_headers += files(
  'gr_api.h',
  'gr_api_client_impl.h',
  'gr_bitops.h',
  'gr_clock.h',
  'gr_errno.h',
  'gr_macro.h',
  'gr_net_compat.h',
  'gr_net_types.h',
)
api_headers += configure_file(
  output: 'gr_version.h',
  configuration: configuration_data({
    'GROUT_VERSION': '"' + meson.project_version() + '"',
  }),
)

api_src = files(
  'printf.c',
  'string.c',
)
src += api_src
cli_src += api_src

api_inc += include_directories('.')

tests += [
  {
    'sources': files('printf_test.c', 'printf.c'),
    'link_args': [],
  },
  {
    'sources': files('string_test.c', 'string.c'),
    'link_args': [],
  },
]
