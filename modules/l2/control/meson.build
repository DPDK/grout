# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

src += files(
  'bridge.c',
  'fdb.c',
  'flood.c',
  'vxlan.c',
)

inc += include_directories('.')

tests += [
  {
    'sources': files('fdb_test.c', 'fdb.c'),
    'link_args': [
      '-Wl,--wrap=rte_hash_lookup_data',
      '-Wl,--wrap=rte_hash_add_key_data',
      '-Wl,--wrap=rte_hash_del_key',
      '-Wl,--wrap=rte_hash_count',
    ],
  },
]
