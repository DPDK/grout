# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Christophe Fontaine
# Copyright (c) 2023 Robin Jarry

project(
  'boring-router',
  'c',
  version: '0.1',
  license: 'BSD-3-Clause',
  meson_version: '>= 0.63.0',
  default_options: [
    'buildtype=debugoptimized',
    'c_std=c11',
    'b_lto=true',
    'b_lto_mode=thin',
    'prefer_static=true',
    'werror=true',
    'warning_level=3',
  ],
)

dpdk_dep = dependency(
  'libdpdk',
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'default_library=static',
    'werror=false',
    'enable_kmods=false',
    'tests=false',
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,net/iavf',
    'disable_libs=table,bpf',
    'disable_apps=*',
    'enable_docs=false',
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
