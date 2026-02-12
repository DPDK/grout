# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

src += files(
  'icmp6_input.c',
  'icmp6_local_send.c',
  'icmp6_output.c',
  'ip6_error.c',
  'ip6_forward.c',
  'ip6_hold.c',
  'ip6_input.c',
  'ip6_loadbalance.c',
  'ip6_local.c',
  'ip6_output.c',
  'ndp_na_input.c',
  'ndp_na_output.c',
  'ndp_ns_input.c',
  'ndp_ns_output.c',
  'ndp_rs_input.c',
)
inc += include_directories('.')

tests += [
  {
    'sources': files('ip6_input.c'),
    'link_args': [],
  },
  {
    'sources': files('ndp_na_input.c'),
    'link_args': [],
  },
]
