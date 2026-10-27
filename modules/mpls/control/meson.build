# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Matej Muzila

src += files(
  'label.c',
  'label_table.c',
  'nexthop.c',
  'resolve.c',
)
inc += include_directories('.')

tests += [
  {
    'sources': files('mpls_test.c', 'label_table.c', 'nexthop.c'),
    'link_args': [
      '-Wl,--wrap=rte_zmalloc',
      '-Wl,--wrap=rte_free',
    ],
  },
]
