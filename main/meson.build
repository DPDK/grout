# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

src += files(
  'api.c',
  'dpdk.c',
  'event.c',
  'main.c',
  'module.c',
  'sd_notify.c',
  'signals.c',
)

inc += include_directories('.')

tests += [
  {
    'sources': files('vec_test.c'),
    'link_args': [],
  },
]
