# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

scdoc_dep = dependency('scdoc', version: '>=1.9.2', native: true)
scdoc = find_program(scdoc_dep.get_variable(pkgconfig: 'scdoc'), native: true)
mandir = get_option('mandir')

man_src = [
  'grout.1.scd',
]

foreach m : man_src
  topic = m.split('.')[-3].split('/')[-1]
  section = m.split('.')[-2]
  output = '@0@.@1@'.format(topic, section)

  custom_target(
    output,
    input: m,
    output: output,
    command: scdoc,
    install: true,
    feed: true,
    capture: true,
    install_dir: '@0@/man@1@'.format(mandir, section),
  )
endforeach
