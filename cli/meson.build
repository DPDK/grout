# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

python = import('python').find_installation('python3')
cffi_gen = files('cffi_gen.py')

cffi_source = custom_target(
  '_br.c',
  output: '_br.c',
  input: api_headers,
  command: [python, cffi_gen, '-o', '@OUTPUT@', '@INPUT@'],
)

ext = python.extension_module(
  '_br', cffi_source,
  c_args: [
    '-Wno-missing-prototypes',
  ],
  link_with: clientlib,
  include_directories: clientlib_include_dirs,
  install: true,
)

alias_target('cffi_ext', ext)

python_sources += files(
  'br/__main__.py',
  'br/c.py',
  'br/cli.py',
)

python.install_sources(python_sources, subdir: 'br')

install_data(
  files('br-cli'),
  install_mode: 'rwxr-xr-x',
  install_dir: get_option('bindir'),
)
