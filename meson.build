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
    'c_std=gnu2x',
    'werror=true',
    'warning_level=2',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_global_arguments('-march=corei7', language: 'c')

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
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,*/iavf,net/null,net/tap',
    'disable_libs=table,bpf',
    'disable_apps=*',
    'enable_docs=false',
  ],
)

event_dep = dependency('libevent')
ecoli_dep = dependency('libecoli', fallback: ['ecoli', 'libecoli_dep'])

src = []
inc = []

lib_src = []
lib_inc = []
api_headers = []

cli_src = []
cli_inc = []

subdir('lib')
subdir('main')
subdir('modules')
subdir('cli')

libbr = shared_library(
  'br',
  lib_src,
  include_directories: lib_inc,
  install: true,
)
import('pkgconfig').generate(libbr)
install_headers(api_headers, subdir: 'br')

executable(
  'br', src,
  include_directories: inc,
  c_args: [
    # required for rte_graph
    '-DALLOW_EXPERIMENTAL_API',
  ],
  dependencies: [dpdk_dep, event_dep],
  install: true,
)

executable(
  'br-cli', cli_src,
  include_directories: lib_inc + cli_inc,
  dependencies: [ecoli_dep],
  link_with: libbr,
  install: true,
)
