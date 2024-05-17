# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

sudo = find_program('sudo')

test_scripts = files(
  'config_test.sh',
  'ip_forward_test.sh',
)

foreach t : test_scripts
  name = fs.replace_suffix(t, '')
  test(name, sudo, args: [t, br_exe, br_cli_exe], suite: 'integration')
endforeach
