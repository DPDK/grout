# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile

if not get_option('pcap').allowed()
  subdir_done()
endif

if pcap_dep.type_name() != 'internal'
  if not compiler.has_header('pcap/pcap-plugin.h', dependencies: pcap_dep)
    # pcap-plugin.h not available — plugin loader not in this libpcap.
    # This is expected on systems with stock libpcap. Skip silently.
    warning('pcap/pcap-plugin.h not available, pcap grout plugin disabled')
    subdir_done()
  endif
endif

pcap_plugin_dir = pcap_dep.get_variable('plugindir')

shared_module(
  'pcap-grout',
  files(
    'pcap-grout.c',
  ),
  include_directories: api_inc,
  dependencies: [pcap_dep],
  name_prefix: '',
  install: true,
  install_dir: pcap_plugin_dir,
)
