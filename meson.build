# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

project(
  'boring-router',
  'c',
  version: '0.1',
  license: 'BSD-3-Clause',
  meson_version: '>= 0.63.0',
  default_options: [
    'buildtype=debug',
    'c_std=c2x',
    'werror=true',
    'warning_level=2',
    'b_lto=true',
    'b_lto_mode=thin',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_project_arguments('-fanalyzer', language: 'c')

dpdk_dep = dependency(
  'libdpdk',
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'c_args=',
    'default_library=static',
    'werror=false',
    'enable_kmods=false',
    'tests=false',
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,*/iavf',
    'disable_libs=table,bpf',
    'disable_apps=*',
    'enable_docs=false',
  ],
)

event_dep = dependency('libevent')

sources = []
include_dirs = []

clientlib_sources = []
clientlib_include_dirs = []
api_headers = []

subdir('clientlib')
subdir('core')
subdir('modules')

executable(
  'br', sources,
  include_directories: include_dirs,
  c_args: [
    # required for rte_graph
    '-DALLOW_EXPERIMENTAL_API',
  ],
  dependencies: [dpdk_dep, event_dep],
  install: true,
)

install_headers(api_headers, subdir: 'br')

clientlib = shared_library(
  'br-client',
  clientlib_sources,
  include_directories: clientlib_include_dirs,
  install: true,
)
import('pkgconfig').generate(clientlib)
