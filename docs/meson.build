# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

scdoc = find_program('scdoc', native: true, required: get_option('docs'))
if not scdoc.found()
  subdir_done()
endif

mandir = get_option('mandir')

# Static man pages
static_man_src = [
  'grout-frr.7.scdoc',
  'grout.8.scdoc',
]

foreach m : static_man_src
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

gen_man = files('gen-man.py')

# Main grcli man page
cli_commands = custom_target(
  'cli_commands.json',
  output: 'cli_commands.json',
  command: [grcli_exe, '--dump-commands'],
  capture: true,
)

grcli_scd = custom_target(
  'grcli.1.scdoc',
  input: cli_commands,
  output: 'grcli.1.scdoc',
  command: gen_man,
  feed: true,
  capture: true,
)

custom_target(
  'grcli.1',
  input: grcli_scd,
  output: 'grcli.1',
  command: scdoc,
  feed: true,
  capture: true,
  install: true,
  install_dir: '@0@/man1'.format(mandir),
  install_tag: 'man',
)

# Individual command man pages
# The list is hardcoded since we can't run grcli during meson configuration.
grcli_commands = [
  'address', 'affinity', 'conntrack', 'dnat44', 'events', 'fdb', 'graph',
  'interface', 'logging', 'nexthop', 'ping', 'ping6', 'route',
  'router-advert', 'snat44', 'stats', 'trace', 'traceroute', 'traceroute6',
  'tunsrc',
]

foreach cmd : grcli_commands
  cmd_scd = custom_target(
    'grcli-@0@.1.scdoc'.format(cmd),
    input: cli_commands,
    output: 'grcli-@0@.1.scdoc'.format(cmd),
    command: [gen_man, cmd],
    capture: true,
    feed: true,
  )
  custom_target(
    'grcli-@0@.1'.format(cmd),
    input: cmd_scd,
    output: 'grcli-@0@.1'.format(cmd),
    command: scdoc,
    install: true,
    feed: true,
    capture: true,
    install_dir: '@0@/man1'.format(mandir),
    install_tag: 'man',
  )
endforeach
