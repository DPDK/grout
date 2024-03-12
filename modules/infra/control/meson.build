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
    'sources': files('rxq_test.c', 'rxq.c', 'port.c', 'worker.c', 'port_config.c'),
    'link_args': [
      '-Wl,--wrap=numa_bitmask_isbitset',
      '-Wl,--wrap=numa_node_of_cpu',
      '-Wl,--wrap=pthread_create',
      '-Wl,--wrap=pthread_join',
      '-Wl,--wrap=rte_dev_name',
      '-Wl,--wrap=rte_eth_dev_configure',
      '-Wl,--wrap=rte_eth_dev_info_get',
      '-Wl,--wrap=rte_eth_dev_start',
      '-Wl,--wrap=rte_eth_dev_stop',
      '-Wl,--wrap=rte_eth_rx_queue_setup',
      '-Wl,--wrap=rte_eth_tx_queue_setup',
      '-Wl,--wrap=rte_free',
      '-Wl,--wrap=rte_get_main_lcore',
      '-Wl,--wrap=rte_mempool_free',
      '-Wl,--wrap=rte_pktmbuf_pool_create',
      '-Wl,--wrap=rte_zmalloc',
    ],
  }
]
