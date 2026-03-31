# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

project(
  'grout',
  'c',
  version: run_command(
    'sh', '-c', 'echo ${GROUT_VERSION:-$(git describe --long --abbrev=8 --dirty 2>/dev/null || echo v0.14.3)}',
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

# C flags that affect preprocessing and struct layout.
# Reused in devtools/check_api.sh for ABI compatibility check.
project_c_flags = [
  '-DALLOW_EXPERIMENTAL_API',
  '-D_GNU_SOURCE',
  '-fms-extensions',
  '-Wno-microsoft',
]
foreach arg : project_c_flags
  add_project_arguments(arg, language: 'c')
endforeach

# additional project C flags (keep alpha sorted)
add_project_arguments('-Wmissing-prototypes', language: 'c')
add_project_arguments('-Wstrict-aliasing=2', language: 'c')
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
  version : '>= 25.11',
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: [
    'c_std=c11',
    'werror=false',
    'tests=false',
    'enable_drivers=net/virtio,net/vhost,net/i40e,net/ice,net/iavf,net/ixgbe,net/null,net/tap,common/mlx5,net/mlx5,bus/auxiliary,net/vmxnet3',
    'enable_libs=graph,hash,fib,rib,pcapng,gso,vhost,cryptodev,dmadev,security',
    'disable_apps=*',
    'enable_docs=false',
    'developer_mode=disabled',
  ],
  static: true,
)

ev_core_dep = dependency('libevent_core')
ev_extra_dep = dependency('libevent_extra')
ev_thread_dep = dependency('libevent_pthreads')
mnl_dep = dependency('libmnl')
numa_dep = dependency('numa')
ecoli_dep = dependency(
  'libecoli',
  version: '>= 0.10.0',
  fallback: ['ecoli', 'libecoli_dep'],
  default_options: [
    'doc=disabled',
    'editline=enabled',
    'examples=disabled',
    'tests=disabled',
    'yaml=disabled',
  ]
)

grout_cflags = []
if dpdk_dep.type_name() == 'internal'
  # subproject: the patch is applied, function is always available
  grout_cflags += ['-DHAVE_RTE_FIB_TBL8_GET_STATS']
elif compiler.has_function(
  'rte_fib_tbl8_get_stats',
  prefix: '#include <rte_fib.h>',
  dependencies: [dpdk_dep],
)
  grout_cflags += ['-DHAVE_RTE_FIB_TBL8_GET_STATS']
endif

src = []
inc = []

api_inc = []
api_headers = []

cli_src = []
cli_inc = []
cli_cflags = []

tests = []

subdir('main')
subdir('modules')
subdir('cli')
subdir('api')
subdir('frr')

fs = import('fs')
abidiff = find_program('abidiff', native: true, required: false)
git = find_program('git', native: true, required: false)
if abidiff.found() and git.found() and fs.is_dir('.git')
  custom_target(
    'api_check',
    output: '.api_check.stamp',
    command: [
      files('devtools/check_api.sh'),
      '-d', abidiff,
      '-o', '@OUTPUT@',
      '-s', meson.project_source_root(),
      '-c', ' '.join(compiler.cmd_array() + ['-std=' + get_option('c_std')] + project_c_flags),
      api_headers,
    ],
    depend_files: api_headers,
    build_by_default: true,
  )
endif

grout_exe = executable(
  'grout', src,
  include_directories: inc + api_inc,
  dependencies: [dpdk_dep, ev_core_dep, ev_extra_dep, ev_thread_dep, mnl_dep, numa_dep],
  c_args: ['-D__GROUT_MAIN__'] + grout_cflags,
  install: true,
)

grcli_exe = executable(
  'grcli', cli_src + grout_header,
  include_directories: cli_inc + api_inc,
  dependencies: [ecoli_dep],
  c_args: cli_cflags + grout_cflags,
  install: true,
)

executable(
  'fib_inject', files('smoke/fib_inject.c') + grout_header,
  include_directories: api_inc,
  install: false,
)

# docs/ must come after grcli_exe since man pages are generated using grcli --man
subdir('docs')

install_headers(api_headers, subdir: 'grout')
pkg = import('pkgconfig')
pkg.generate(
  name: 'grout',
  description: 'grout API headers',
  subdirs: ['grout'],
  install_dir: get_option('datadir') / 'pkgconfig',
)

cmocka_dep = dependency('cmocka', required: get_option('tests'))
if cmocka_dep.found()
  foreach t : tests
    name = fs.replace_suffix(t['sources'].get(0), '').underscorify()
    t += {
      'sources': t['sources'] + files('api/string.c'),
      'include_directories': inc + api_inc,
      'c_args': ['-D__GROUT_MAIN__', '-D__GROUT_UNIT_TEST__'],
      'link_args': t['link_args'],
      'dependencies': [dpdk_dep, ev_core_dep, ev_thread_dep, numa_dep, ecoli_dep, cmocka_dep],
    }
    test(name, executable(name, kwargs: t), suite: 'unit')
  endforeach
endif
