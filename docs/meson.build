# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

md2man = find_program('go-md2man', native: true, required: get_option('docs'))
if not md2man.found()
  subdir_done()
endif

mandir = get_option('mandir')
config = configuration_data({
  'VERSION': meson.project_version(),
  'DATE': run_command('date', '+%Y-%m-%d', check: false, capture: true).stdout().strip(),
})

man_src = [
  'grcli.1.md',
  'grout.8.md',
]

foreach m : man_src
  topic = m.split('.')[-3].split('/')[-1]
  section = m.split('.')[-2]
  output = '@0@.@1@'.format(topic, section)

  c = configure_file(
    input: m,
    output: '@0@.md'.format(output),
    configuration: config,
  )
  custom_target(
    output,
    input: c,
    output: output,
    command: md2man,
    install: true,
    feed: true,
    capture: true,
    install_dir: '@0@/man@1@'.format(mandir, section),
    install_tag: 'man',
  )
endforeach
