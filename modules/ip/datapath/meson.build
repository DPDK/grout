# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

src += files(
  'arp_input.c',
  'arp_input_reply.c',
  'arp_input_request.c',
  'arp_output_reply.c',
  'arp_output_request.c',
  'dnat44.c',
  'fib4.c',
  'icmp_input.c',
  'icmp_local_send.c',
  'icmp_output.c',
  'ip_error.c',
  'ip_forward.c',
  'ip_hold.c',
  'ip_input.c',
  'ip_local.c',
  'ip_output.c',
  'snat44.c',
)
inc += include_directories('.')

tests += [
  {
    'sources': files('ip_input.c'),
    'link_args': [],
  }
]
