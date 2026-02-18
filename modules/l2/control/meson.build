# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

src += files(
  'bridge.c',
  'fdb.c',
  'flood.c',
  'iface_security.c',
  'l2_stats.c',
  'rstp.c',
  'vxlan.c',
)

inc += include_directories('.')

tests += [
  {
    'sources': files('l2_hooks_test.c', 'bridge.c'),
    'link_args': [],
  },
  {
    'sources': files('rstp_test.c', 'rstp.c', 'bridge.c'),
    'link_args': [
      '-Wl,--wrap=rte_zmalloc',
      '-Wl,--wrap=rte_free',
    ],
  },
]
