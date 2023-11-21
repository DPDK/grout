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
    'b_lto=true',
    'b_lto_mode=thin',
    'werror=true',
    'warning_level=2',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')

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
cmdline_gen_py = find_program('dpdk-cmdline-gen.py')
cmdline_gen = [
  cmdline_gen_py,
  '--context-name=commands_context',
  '--output-file=@OUTPUT@',
  '@INPUT@',
]

protoc_c = find_program('protoc-c')
proto_dep = dependency('libprotobuf-c')
proto_gen = [
  protoc_c,
  '--proto_path=@CURRENT_SOURCE_DIR@',
  '--c_out=@OUTDIR@',
  '--fatal_warnings',
  '@INPUT@',
]
proto_output = ['@BASENAME@.pb-c.h', '@BASENAME@.pb-c.c']

event_dep = dependency('libevent')

sources = []
include_dirs = []
client_sources = []
client_include_dirs = []
api_headers = []

subdir('client')
subdir('core')
subdir('modules')

executable(
  'br', sources,
  include_directories: include_dirs,
  c_args: [
    # required for rte_graph
    '-DALLOW_EXPERIMENTAL_API',
  ],
  dependencies: [dpdk_dep, proto_dep, event_dep],
  install: true,
)

install_headers(api_headers, subdir: 'br')

executable(
  'br-cli', client_sources,
  include_directories: include_dirs + client_include_dirs,
  dependencies: [dpdk_dep, proto_dep],
  install: true,
)
