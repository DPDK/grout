# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

api_headers += files(
  'gr_api.h',
  'gr_api_client_impl.h',
  'gr_bitops.h',
  'gr_errno.h',
  'gr_macro.h',
  'gr_net_compat.h',
  'gr_net_types.h',
)

src += files('printf.c')
cli_src += files('printf.c')

api_inc += include_directories('.')

tests += [
  {
    'sources': files('printf_test.c', 'printf.c'),
    'link_args': [],
  },
]
