# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Christophe Fontaine
# Copyright (c) 2023 Robin Jarry

project(
  'boring-router',
  'c',
  version: '0.1',
  license: 'BSD-3-Clause',
  meson_version: '>= 0.63.0',
)

dpdk_dep = dependency(
  'libdpdk',
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: [
  ],
)
capnpc_c = find_program('capnpc-c')
capnp_dep = dependency(
  'libcapnp',
  fallback: ['c-capnproto', 'libcapnp_dep'],
)

sources = []
dependencies = [dpdk_dep, capnp_dep]

subdir('core')

executable('brouter', sources, dependencies: dependencies)
