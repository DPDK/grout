# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

test_scripts = files(
  'config_test.sh',
  'ip_forward_test.sh',
  'vrf_forward_test.sh',
)

sudo = find_program('sudo', required: false)
tcpdump = find_program('tcpdump', required: false)
ping = find_program('ping', required: false)
ip = find_program('ip', required: false)
if sudo.found() and tcpdump.found() and ping.found() and ip.found()
  foreach t : test_scripts
    if run_command(sudo, '-ll', t, check: false).returncode() == 0
      name = fs.replace_suffix(t, '')
      test(name,
        sudo, args: [t, meson.project_build_root()],
        depends: [br_exe, br_cli_exe],
        suite: 'integration',
      )
    endif
  endforeach
endif
