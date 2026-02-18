# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

src += files(
  'bridge.c',
  'dai.c',
  'dhcp_snooping.c',
  'fdb.c',
  'flood.c',
  'iface_security.c',
  'ipsg.c',
  'l2_stats.c',
  'lldp.c',
  'mcast_snooping.c',
  'port_mirror.c',
  'qos.c',
  'rstp.c',
  'storm_control.c',
  'vlan_filtering.c',
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
  {
    'sources': files('vlan_filtering_test.c', 'vlan_filtering.c'),
    'link_args': [
      '-Wl,--wrap=rte_zmalloc',
      '-Wl,--wrap=rte_free',
    ],
  },
  {
    'sources': files('mcast_snooping_test.c', 'mcast_snooping.c'),
    'link_args': [],
  },
  {
    'sources': files('port_mirror_test.c', 'port_mirror.c'),
    'link_args': [],
  },
  {
    'sources': files('qos_test.c', 'qos.c'),
    'link_args': [],
    'c_args': ['-D__GROUT_UNIT_TEST__'],
  },
  {
    'sources': files('storm_control_test.c', 'storm_control.c'),
    'link_args': [
      '-Wl,--wrap=rte_rdtsc',
      '-Wl,--wrap=rte_meter_trtcm_profile_config',
      '-Wl,--wrap=rte_meter_trtcm_config',
    ],
    'c_args': ['-D__GROUT_UNIT_TEST__'],
  },
]
