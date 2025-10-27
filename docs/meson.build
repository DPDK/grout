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

# Static man pages
static_man_src = [
  'grout.8.md',
  'grout-frr.7.md',
]

foreach m : static_man_src
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

# Dynamic grcli man pages
# During cross-compilation, skip man page generation since native dependencies
# (libecoli, libsmartcols) are not available for the build machine.
if meson.is_cross_build()
  warning('Cross-compilation detected: skipping grcli man page generation')
  subdir_done()
endif

# Main grcli man page
grcli_md = custom_target(
  'grcli.1.md',
  output: 'grcli.1.md',
  command: [grcli_exe, '--man'],
  capture: true,
)
custom_target(
  'grcli.1',
  input: grcli_md,
  output: 'grcli.1',
  command: md2man,
  install: true,
  feed: true,
  capture: true,
  install_dir: '@0@/man1'.format(mandir),
  install_tag: 'man',
)

# Individual command man pages
# The list is hardcoded since we can't run grcli during meson configuration.
grcli_commands = [
  'address', 'affinity', 'conntrack', 'dnat44', 'events',
  'graph', 'interface', 'logging', 'nexthop', 'ping',
  'quit', 'route', 'router-advert', 'snat44', 'stats',
  'trace', 'traceroute', 'tunsrc',
]

foreach cmd : grcli_commands
  cmd_md = custom_target(
    'grcli-@0@.1.md'.format(cmd),
    output: 'grcli-@0@.1.md'.format(cmd),
    command: [grcli_exe, '--man', cmd],
    capture: true,
  )
  custom_target(
    'grcli-@0@.1'.format(cmd),
    input: cmd_md,
    output: 'grcli-@0@.1'.format(cmd),
    command: md2man,
    install: true,
    feed: true,
    capture: true,
    install_dir: '@0@/man1'.format(mandir),
    install_tag: 'man',
  )
endforeach
