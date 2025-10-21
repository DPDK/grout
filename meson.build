# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

project(
  'grout',
  'c',
  version: run_command(
    'sh', '-c', 'echo ${GROUT_VERSION:-$(git describe --long --abbrev=8 --dirty 2>/dev/null || echo v0.13.0)}',
    check: false,
    capture: true,
  ).stdout().strip(),
  license: 'BSD-3-Clause AND GPL-2.0-or-later',
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
add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_project_arguments('-Wno-microsoft', language: 'c')
add_project_arguments('-Wstrict-aliasing=2', language: 'c')
add_project_arguments('-fms-extensions', language: 'c')
add_project_arguments('-fstrict-aliasing', language: 'c')

# optional project C flags (keep alpha sorted)
optional_c_args = [
  '-Wcalloc-transposed-args',
  '-Wmissing-variable-declarations',
  '-Wno-format-truncation',
]
compiler = meson.get_compiler('c')
foreach arg : optional_c_args
  if compiler.has_argument(arg)
    add_project_arguments(arg, language: 'c')
  endif
endforeach

if not compiler.compiles('''
  #include <stdint.h>
  enum foo : uint16_t { X = 0, A = 2, B = 8 };
  int main(void) { return X; }
  ''', name: 'C23 enum underlying types')
  error(compiler.get_id(), compiler.version(), 'does not support C23 enum underlying types')
endif

if not compiler.compiles('''
  #define FOO(x, ...) (x __VA_OPT__(,) __VA_ARGS__)
  int main(void) { return FOO(0); }
  ''', name: 'C23 __VA_OPT__ macro')
  error(compiler.get_id(), compiler.version(), 'does not support C23 __VA_OPT__ macro')
endif

dpdk_dep = dependency(
  'libdpdk',
  version : '>= 24.11.1',
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'werror=false',
    'enable_kmods=false',
    'tests=false',
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,common/iavf,net/iavf,net/ixgbe,net/null,net/tap,common/mlx5,net/mlx5,bus/auxiliary,net/vmxnet3',
    'enable_libs=graph,hash,fib,rib,pcapng,gso,vhost,cryptodev,dmadev,security',
    'disable_apps=*',
    'enable_docs=false',
    'developer_mode=disabled',
  ],
  static: get_option('dpdk_static'),
)

ev_core_dep = dependency('libevent_core')
ev_thread_dep = dependency('libevent_pthreads')
numa_dep = dependency('numa')
ecoli_dep = dependency(
  'libecoli',
  version: '>= 0.8.0',
  fallback: ['ecoli', 'libecoli_dep'],
  default_options: [
    'doc=disabled',
    'editline=enabled',
    'examples=disabled',
    'tests=disabled',
    'yaml=disabled',
  ]
)
smartcols_dep = dependency('smartcols')

src = []
inc = []

api_inc = []
api_headers = []

cli_src = []
cli_inc = []
cli_cflags = []

tests = []

subdir('docs')
subdir('api')
subdir('main')
subdir('modules')
subdir('cli')
subdir('frr')

grout_exe = executable(
  'grout', src,
  include_directories: inc + api_inc,
  dependencies: [dpdk_dep, ev_core_dep, ev_thread_dep, numa_dep],
  c_args: ['-D__GROUT_MAIN__'],
  install: true,
)

grcli_exe = executable(
  'grcli', cli_src,
  include_directories: cli_inc + api_inc,
  dependencies: [ecoli_dep, smartcols_dep],
  c_args: cli_cflags,
  install: true,
)

install_headers(api_headers)

cmocka_dep = dependency('cmocka', required: get_option('tests'))
if cmocka_dep.found()
  fs = import('fs')
  coverage_c_args = []
  coverage_link_args = []
  if compiler.get_id() == 'gcc'
    coverage_c_args += ['-coverage']
    coverage_link_args += ['-lgcov']
  endif
  foreach t : tests
    name = fs.replace_suffix(t['sources'].get(0), '').underscorify()
    t += {
      'sources': t['sources'] + files('api/string.c'),
      'include_directories': inc + api_inc,
      'c_args': ['-D__GROUT_MAIN__', '-D__GROUT_UNIT_TEST__'] + coverage_c_args,
      'link_args': t['link_args'] + coverage_link_args,
      'dependencies': [dpdk_dep, ev_core_dep, ev_thread_dep, numa_dep, ecoli_dep, cmocka_dep],
    }
    test(name, executable(name, kwargs: t), suite: 'unit')
  endforeach
endif
