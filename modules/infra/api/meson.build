# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

src += files(
  'affinity.c',
  'iface.c',
  'nexthop.c',
  'stats.c',
  'trace.c',
)

api_headers += files(
  'gr_capture.h',
  'gr_infra.h',
  'gr_nexthop.h',
)
api_inc += include_directories('.')

tests += [
  {
    'sources': files('capture_ring_test.c'),
    'link_args': [],
  },
]
