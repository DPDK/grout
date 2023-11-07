# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Christophe Fontaine
# Copyright (c) 2023 Robin Jarry

project('boring-router', 'c',
  version: run_command('git', 'describe', '--always', check: false).stdout().strip(),
  license: 'BSD-3-Clause',
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'default_library=static',
    'warning_level=2',
  ],
  meson_version: '>= 0.53.2',
)

executable('brouter', 'core/main.c')
