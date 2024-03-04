# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

src += files(
  'port.c',
  'port_config.c',
  'worker.c',
  'graph.c',
  'rxq.c',
)

tests += [
  {
    'sources': files('rxq_test.c', 'rxq.c', 'port.c', 'worker.c'),
    'link_args': [
      '-Wl,--wrap=rte_get_main_lcore',
      '-Wl,--wrap=numa_bitmask_isbitset',
      '-Wl,--wrap=pthread_create',
      '-Wl,--wrap=pthread_join',
      '-Wl,--wrap=rte_zmalloc',
      '-Wl,--wrap=rte_free',
    ],
  }
]
