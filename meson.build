# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

project(
  'boring-router',
  'c',
  version: '0.1',
  license: 'BSD-3-Clause',
  meson_version: '>= 0.63.0',
  default_options: [
    'buildtype=release',
    'c_std=gnu2x',
    'werror=false',
    'warning_level=1',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_project_arguments('-Wno-format-truncation', language: 'c')

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
numa_dep = dependency('numa')
ecoli_dep = dependency('libecoli', fallback: ['ecoli', 'libecoli_dep'])

src = []
inc = []

lib_src = []
lib_inc = []
api_headers = []

cli_src = []
cli_inc = []

tests = []

subdir('docs')
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
  dependencies: [dpdk_dep, event_dep, numa_dep],
  install: true,
)

executable(
  'br-cli', cli_src,
  include_directories: lib_inc + cli_inc,
  dependencies: [ecoli_dep],
  link_with: libbr,
  install: true,
)

fs = import('fs')
cmocka_dep = dependency('cmocka')

foreach t : tests
  name = fs.replace_suffix(t['sources'].get(0), '').underscorify()
  t += {
    'sources': t['sources'] + files('main/stb_ds_impl.c', 'main/string.c'),
    'include_directories': inc + lib_inc + cli_inc,
    'c_args': ['-coverage'],
    'link_args': t['link_args'] + ['-lgcov'],
    'dependencies': [dpdk_dep, event_dep, numa_dep, ecoli_dep, cmocka_dep],
  }
  test(name, executable(name, kwargs: t))
endforeach
