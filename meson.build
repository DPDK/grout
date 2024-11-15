# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

project(
  'grout',
  'c',
  version: run_command(
    'sh', '-c', 'git describe --long --abbrev=8 --dirty 2>/dev/null || echo v0.2',
    check: false,
    capture: true,
  ).stdout().strip(),
  license: 'BSD-3-Clause',
  meson_version: '>= 0.63.0',
  default_options: [
    'buildtype=release',
    'c_std=gnu2x',
    'werror=false',
    'warning_level=1',
  ],
)

# additional project C flags (keep alpha sorted)
add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')
add_project_arguments('-DGROUT_VERSION="' + meson.project_version() + '"', language: 'c')
add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_project_arguments('-Wno-format-truncation', language: 'c')
add_project_arguments('-Wstrict-aliasing=2', language: 'c')
add_project_arguments('-fstrict-aliasing', language: 'c')

# optional project C flags (keep alpha sorted)
optional_c_args = [
  '-Wcalloc-transposed-args',
  '-Wmissing-variable-declarations',
]
compiler = meson.get_compiler('c')
foreach arg : optional_c_args
  if compiler.has_argument(arg)
    add_project_arguments(arg, language: 'c')
  endif
endforeach

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
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,common/iavf,net/iavf,net/ixgbe,net/null,net/tap,common/mlx5,net/mlx5,bus/auxiliary',
    'enable_libs=graph,hash,fib,rib,pcapng,gso,vhost,cryptodev,dmadev,security',
    'disable_apps=*',
    'enable_docs=false',
    'developer_mode=disabled',
  ],
)

ev_core_dep = dependency('libevent_core')
ev_thread_dep = dependency('libevent_pthreads')
numa_dep = dependency('numa')
ecoli_dep = dependency('libecoli', fallback: ['ecoli', 'libecoli_dep'])
smartcols_dep = dependency('smartcols')

src = []
inc = []

api_inc = []
api_headers = []

cli_src = []
cli_inc = []

tests = []

subdir('docs')
subdir('api')
subdir('main')
subdir('modules')
subdir('cli')

grout_exe = executable(
  'grout', src,
  include_directories: inc + api_inc,
  dependencies: [dpdk_dep, ev_core_dep, ev_thread_dep, numa_dep],
  c_args: ['-D__GROUT_MAIN__'],
  install: true,
  install_dir: 'sbin',
)

grcli_exe = executable(
  'grcli', cli_src,
  include_directories: cli_inc + api_inc,
  dependencies: [ecoli_dep, smartcols_dep],
  install: true,
)

install_headers(api_headers)

cmocka_dep = dependency('cmocka', required: get_option('tests'))
if cmocka_dep.found()
  fs = import('fs')
  foreach t : tests
    name = fs.replace_suffix(t['sources'].get(0), '').underscorify()
    t += {
      'sources': t['sources'] + files('main/string.c'),
      'include_directories': inc + api_inc,
      'c_args': ['-coverage', '-D__GROUT_MAIN__'],
      'link_args': t['link_args'] + ['-lgcov'],
      'dependencies': [dpdk_dep, ev_core_dep, ev_thread_dep, numa_dep, ecoli_dep, cmocka_dep],
    }
    test(name, executable(name, kwargs: t), suite: 'unit')
  endforeach
endif
