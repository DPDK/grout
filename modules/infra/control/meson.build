# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

src += files(
  'control_output.c',
  'iface.c',
  'loopback.c',
  'mempool.c',
  'nexthop.c',
  'port.c',
  'worker.c',
  'graph.c',
  'vlan.c',
  'vrf.c',
)
inc += include_directories('.')

tests += [
  {
    'sources': files('worker_test.c', 'port.c', 'worker.c'),
    'link_args': [
      '-Wl,--wrap=numa_available',
      '-Wl,--wrap=numa_node_of_cpu',
      '-Wl,--wrap=pthread_cancel',
      '-Wl,--wrap=pthread_cond_wait',
      '-Wl,--wrap=pthread_cond_timedwait',
      '-Wl,--wrap=pthread_create',
      '-Wl,--wrap=pthread_join',
      '-Wl,--wrap=rte_dev_name',
      '-Wl,--wrap=rte_eth_dev_configure',
      '-Wl,--wrap=rte_eth_dev_get_mtu',
      '-Wl,--wrap=rte_eth_dev_info_get',
      '-Wl,--wrap=rte_eth_dev_socket_id',
      '-Wl,--wrap=rte_eth_dev_start',
      '-Wl,--wrap=rte_eth_dev_stop',
      '-Wl,--wrap=rte_eth_macaddr_get',
      '-Wl,--wrap=rte_eth_rx_queue_setup',
      '-Wl,--wrap=rte_eth_tx_queue_setup',
      '-Wl,--wrap=rte_free',
      '-Wl,--wrap=rte_mempool_free',
      '-Wl,--wrap=rte_pktmbuf_pool_create',
      '-Wl,--wrap=rte_zmalloc',
    ],
  }
]
