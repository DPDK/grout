project('libpcap', 'c',
  version: run_command('sed', '-n', '1p', 'VERSION', check: true).stdout().strip(),
  license: 'BSD-3-Clause',
  default_options: ['c_std=gnu99'],
  meson_version: '>= 0.63.0',
)

pkgconfig = import('pkgconfig')
cc = meson.get_compiler('c')
system = host_machine.system()

#
# Version parsing.
#
version = meson.project_version()
version_parts = version.split('.')
version_major = version_parts[0]
version_minor = version_parts[1]
# Strip any suffix like -PRE-GIT from the patch component.
version_patch = version_parts[2].split('-')[0]
lib_version = '@0@.@1@.@2@'.format(version_major, version_minor, version_patch)

#
# Configuration data for generated config.h.
#
cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', version)
cdata.set_quoted('PACKAGE_NAME', 'pcap')
cdata.set_quoted('PACKAGE_STRING', 'pcap ' + version)
cdata.set_quoted('PACKAGE_TARNAME', 'libpcap')
cdata.set_quoted('PACKAGE_URL', 'https://www.tcpdump.org/')
cdata.set_quoted('PACKAGE_BUGREPORT',
  'https://github.com/the-tcpdump-group/libpcap/issues')
cdata.set('SIZEOF_VOID_P', cc.sizeof('void *'))
cdata.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix: '#include <time.h>'))

#
# Options.
#
capture_type = get_option('capture_type')
opt_remote = get_option('remote')
plugin_dir = get_option('plugin_dir')
if plugin_dir == ''
  plugin_dir = get_option('prefix') / get_option('libdir') / 'pcap' / 'plugins'
endif

if not get_option('protochain')
  cdata.set('NO_PROTOCHAIN', 1)
endif
if get_option('yydebug')
  cdata.set('YYDEBUG', 1)
endif
if get_option('optimizer_debug')
  cdata.set('BDEBUG', 1)
endif
if opt_remote
  cdata.set('ENABLE_REMOTE', 1)
endif

#
# Large file support.
#
if system != 'windows'
  add_project_arguments('-D_FILE_OFFSET_BITS=64', language: 'c')
  if cc.has_function('fseeko',
      prefix: '#define _LARGEFILE_SOURCE\n#include <stdio.h>')
    cdata.set('HAVE_FSEEKO', 1)
    add_project_arguments('-D_LARGEFILE_SOURCE', language: 'c')
  endif
endif

#
# Header checks.
#
_header_checks = {
  'unistd.h': 'HAVE_UNISTD_H',
  'net/if_media.h': 'HAVE_NET_IF_MEDIA_H',
  'sys/ioccom.h': 'HAVE_SYS_IOCCOM_H',
  'sys/bufmod.h': 'HAVE_SYS_BUFMOD_H',
  'sys/dlpi.h': 'HAVE_SYS_DLPI_H',
  'sys/dlpi_ext.h': 'HAVE_SYS_DLPI_EXT_H',
  'machine/atomic.h': 'HAVE_MACHINE_ATOMIC_H',
}
foreach h, define : _header_checks
  if cc.has_header(h)
    cdata.set(define, 1)
  endif
endforeach

have_unistd = cdata.has('HAVE_UNISTD_H')
extra_cflags = []
if not have_unistd
  extra_cflags += ['-DYY_NO_UNISTD_H']
endif

#
# Function checks.
#
have_strlcpy = cc.has_function('strlcpy')
have_strlcat = cc.has_function('strlcat')
have_strtok_r = cc.has_function('strtok_r')
have_asprintf = cc.has_function('asprintf')
have_vasprintf = cc.has_function('vasprintf')

_func_checks = {
  'strlcpy': have_strlcpy,
  'strlcat': have_strlcat,
  'strtok_r': have_strtok_r,
  'asprintf': have_asprintf,
  'vasprintf': have_vasprintf,
  'snprintf': cc.has_function('snprintf'),
  'vsnprintf': cc.has_function('vsnprintf'),
  'secure_getenv': cc.has_function('secure_getenv'),
  'issetugid': cc.has_function('issetugid'),
  'getauxval': cc.has_function('getauxval'),
  'getspnam': cc.has_function('getspnam'),
  'ether_hostton': cc.has_function('ether_hostton'),
}
foreach f, result : _func_checks
  if result
    cdata.set('HAVE_@0@'.format(f.to_upper()), 1)
  endif
endforeach

#
# strerror_r variant detection.
#
if cc.has_function('strerror_r')
  if cc.compiles('''
    #define _GNU_SOURCE
    #include <string.h>
    extern char *strerror_r(int, char *, size_t);
    int main(void) { return 0; }
  ''', name: 'GNU strerror_r')
    cdata.set('HAVE_GNU_STRERROR_R', 1)
  else
    cdata.set('HAVE_POSIX_STRERROR_R', 1)
  endif
endif

#
# Type and struct member checks.
#
if system != 'windows'
  if cc.has_type('socklen_t', prefix: '#include <sys/socket.h>')
    cdata.set('HAVE_SOCKLEN_T', 1)
  endif
  if cc.has_member('struct sockaddr', 'sa_len',
      prefix: '#include <sys/socket.h>')
    cdata.set('HAVE_STRUCT_SOCKADDR_SA_LEN', 1)
  endif
endif

#
# Detect libc variant (glibc, uclibc).
#
if system == 'linux'
  if cc.has_header_symbol('features.h', '__GLIBC__')
    cdata.set('HAVE_GLIBC', 1)
  elif cc.has_header_symbol('features.h', '__UCLIBC__')
    cdata.set('HAVE_UCLIBC', 1)
  endif
endif

#
# getnetbyname_r variant detection.
#
if cc.has_header_symbol('netdb.h', 'getnetbyname_r')
  if cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct netent netent_buf;
      char buf[1024];
      struct netent *resultp;
      int h_errnoval;
      return getnetbyname_r((const char *)0, &netent_buf, buf,
                            sizeof buf, &resultp, &h_errnoval);
    }
  ''', name: 'Linux getnetbyname_r')
    cdata.set('HAVE_LINUX_GETNETBYNAME_R', 1)
  elif cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct netent netent_buf;
      char buf[1024];
      return getnetbyname_r((const char *)0, &netent_buf, buf,
                            (int)sizeof buf) != NULL;
    }
  ''', name: 'Solaris getnetbyname_r')
    cdata.set('HAVE_SOLARIS_GETNETBYNAME_R', 1)
  elif cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct netent netent_buf;
      struct netent_data net_data;
      return getnetbyname_r((const char *)0, &netent_buf, &net_data);
    }
  ''', name: 'AIX getnetbyname_r')
    cdata.set('HAVE_AIX_GETNETBYNAME_R', 1)
  endif
endif

#
# getprotobyname_r variant detection.
#
if cc.has_header_symbol('netdb.h', 'getprotobyname_r')
  if cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct protoent protoent_buf;
      char buf[1024];
      struct protoent *resultp;
      return getprotobyname_r((const char *)0, &protoent_buf, buf,
                              sizeof buf, &resultp);
    }
  ''', name: 'Linux getprotobyname_r')
    cdata.set('HAVE_LINUX_GETPROTOBYNAME_R', 1)
  elif cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct protoent protoent_buf;
      char buf[1024];
      return getprotobyname_r((const char *)0, &protoent_buf, buf,
                              (int)sizeof buf) != NULL;
    }
  ''', name: 'Solaris getprotobyname_r')
    cdata.set('HAVE_SOLARIS_GETPROTOBYNAME_R', 1)
  elif cc.compiles('''
    #include <netdb.h>
    int main(void) {
      struct protoent protoent_buf;
      struct protoent_data proto_data;
      return getprotobyname_r((const char *)0, &protoent_buf, &proto_data);
    }
  ''', name: 'AIX getprotobyname_r')
    cdata.set('HAVE_AIX_GETPROTOBYNAME_R', 1)
  endif
endif

#
# ether_hostton declaration detection.
#
if cc.has_function('ether_hostton')
  _ether_hdrs = [
    ['net/ethernet.h', 'NET_ETHERNET_H_DECLARES_ETHER_HOSTTON'],
    ['netinet/ether.h', 'NETINET_ETHER_H_DECLARES_ETHER_HOSTTON'],
    ['sys/ethernet.h', 'SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON'],
    ['arpa/inet.h', 'ARPA_INET_H_DECLARES_ETHER_HOSTTON'],
  ]
  _have_decl = false
  foreach pair : _ether_hdrs
    if not _have_decl and cc.has_header_symbol(pair[0], 'ether_hostton',
        required: false)
      cdata.set(pair[1], 1)
      cdata.set('HAVE_DECL_ETHER_HOSTTON', 1)
      _have_decl = true
    endif
  endforeach
  if not _have_decl and cc.compiles('''
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    void *p = (void *)ether_hostton;
    int main(void) { return p != 0; }
  ''', name: 'ether_hostton in netinet/if_ether.h')
    cdata.set('NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON', 1)
    cdata.set('HAVE_DECL_ETHER_HOSTTON', 1)
    _have_decl = true
  endif
  if not _have_decl
    # Check for struct ether_addr for our own declaration.
    if cc.has_type('struct ether_addr',
        prefix: '''#include <sys/types.h>
                   #include <sys/socket.h>
                   #include <net/if.h>
                   #include <netinet/in.h>
                   #include <netinet/if_ether.h>''')
      cdata.set('HAVE_STRUCT_ETHER_ADDR', 1)
    endif
  endif
endif

#
# Atomic builtins (needed for Linux memory-mapped capture).
#
if cc.compiles('''
  int main(void) {
    int i = 17;
    return __atomic_load_n(&i, __ATOMIC_RELAXED);
  }
''', name: '__atomic_load_n')
  cdata.set('HAVE___ATOMIC_LOAD_N', 1)
endif
if cc.compiles('''
  int main(void) {
    int i;
    __atomic_store_n(&i, 17, __ATOMIC_RELAXED);
    return 0;
  }
''', name: '__atomic_store_n')
  cdata.set('HAVE___ATOMIC_STORE_N', 1)
endif

#
# Platform libraries.
#
pcap_deps = []
pcap_libs_private = []
requires_private = []

dl_dep = cc.find_library('dl', required: false)
if dl_dep.found()
  pcap_deps += dl_dep
endif

if system == 'haiku'
  pcap_deps += cc.find_library('bsd')
  pcap_deps += cc.find_library('network')
elif system == 'sunos'
  _socket = cc.find_library('socket', required: false)
  _nsl = cc.find_library('nsl', required: false)
  if _socket.found()
    pcap_deps += _socket
    pcap_libs_private += '-lsocket'
  endif
  if _nsl.found()
    pcap_deps += _nsl
    pcap_libs_private += '-lnsl'
  endif
  cdata.set('HAVE_SOLARIS', 1)
endif

#
# Capture type auto-detection.
#
if capture_type == ''
  if system == 'linux'
    capture_type = 'linux'
  elif system == 'haiku'
    capture_type = 'haiku'
  elif system == 'gnu'
    capture_type = 'hurd'
  elif cc.has_header('net/bpf.h', prefix: '#include <sys/types.h>')
    _biocsetif_prefix = '''
      #include <sys/types.h>
      #include <sys/time.h>
      #include <sys/ioctl.h>
      #include <sys/socket.h>
    '''
    if cdata.has('HAVE_SYS_IOCCOM_H')
      _biocsetif_prefix += '#include <sys/ioccom.h>\n'
    endif
    _biocsetif_prefix += '''
      #include <net/bpf.h>
      #include <net/if.h>
    '''
    if cc.compiles(_biocsetif_prefix + '''
      int main(void) { int x = BIOCSETIF; return x; }
    ''', name: 'BIOCSETIF in net/bpf.h')
      capture_type = 'bpf'
    endif
  endif
  if capture_type == ''
    if cc.has_header('sys/dlpi.h')
      capture_type = 'dlpi'
    else
      error('No supported packet capture interface found.\n' +
            'Use -Dcapture_type=null for a read-only libpcap.')
    endif
  endif
endif
message('Packet capture mechanism: ' + capture_type)

#
# Common source files.
#
common_src = files(
  'bpf_dump.c',
  'bpf_filter.c',
  'bpf_image.c',
  'etherent.c',
  'fmtutils.c',
  'gencode.c',
  'nametoaddr.c',
  'optimize.c',
  'pcap-common.c',
  'pcap-util.c',
  'pcap.c',
  'pcap-new.c',
  'savefile.c',
  'sf-pcap.c',
  'sf-pcapng.c',
  'pcap-plugin.c',
)

#
# Platform-specific capture source.
#
platform_src = files('pcap-' + capture_type + '.c')

#
# Missing function fallbacks.
#
if not have_asprintf
  common_src += files('missing/asprintf.c')
endif
if not have_strlcat
  common_src += files('missing/strlcat.c')
endif
if not have_strlcpy
  common_src += files('missing/strlcpy.c')
endif
if not have_strtok_r
  common_src += files('missing/strtok_r.c')
endif

#
# Capture-type-specific extras.
#
if capture_type == 'dlpi'
  platform_src += files('dlpisubs.c')
  _libdlpi = cc.find_library('dlpi', required: false)
  if _libdlpi.found() and cc.has_function('dlpi_walk', dependencies: _libdlpi)
    pcap_deps += _libdlpi
    pcap_libs_private += '-ldlpi'
    # Replace pcap-dlpi.c with pcap-libdlpi.c.
    platform_src = files('pcap-libdlpi.c', 'dlpisubs.c')
    cdata.set('HAVE_LIBDLPI', 1)
  endif
  # DLPI passive mode.
  if cc.has_type('dl_passive_req_t',
      prefix: '#include <sys/types.h>\n#include <sys/dlpi.h>')
    cdata.set('HAVE_DL_PASSIVE_REQ_T', 1)
  endif
elif capture_type == 'hurd'
  _rt = cc.find_library('rt')
  pcap_deps += _rt
  pcap_libs_private += '-lrt'
elif capture_type == 'bpf'
  cdata.set('HAVE_NET_BPF_H', 1)
  # BPF_TIMEVAL struct.
  _bpf_timeval_prefix = '#include <sys/types.h>\n'
  if cdata.has('HAVE_SYS_IOCCOM_H')
    _bpf_timeval_prefix += '#include <sys/ioccom.h>\n'
  endif
  _bpf_timeval_prefix += '#include <net/bpf.h>\n'
  if cc.has_type('struct BPF_TIMEVAL', prefix: _bpf_timeval_prefix)
    cdata.set('HAVE_STRUCT_BPF_TIMEVAL', 1)
  endif
  if system == 'sunos'
    # Solaris "any" device.
    if cc.has_header_symbol('inet/ipnet.h', 'IPNET_ANY_LINK')
      cdata.set('HAVE_SOLARIS_ANY_DEVICE', 1)
    endif
  endif
  # AIX BPF needs libodm and libcfg.
  if system == 'aix'
    pcap_deps += cc.find_library('odm')
    pcap_deps += cc.find_library('cfg')
    pcap_libs_private += ['-lodm', '-lcfg']
  endif
endif

#
# Find-all-devices method.
#
if capture_type != 'null'
  if cc.has_function('getifaddrs') and cc.has_header('ifaddrs.h',
      prefix: '#include <sys/types.h>')
    platform_src += files('fad-getad.c')
  elif cc.compiles('''
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <sys/sockio.h>
    int main(void) { ioctl(0, SIOCGLIFCONF, (char *)0); return 0; }
  ''', name: 'SIOCGLIFCONF')
    platform_src += files('fad-glifc.c')
  else
    platform_src += files('fad-gifc.c')
  endif
endif

#
# Linux-specific checks.
#
if system == 'linux'
  if cc.has_header('linux/net_tstamp.h')
    cdata.set('HAVE_LINUX_NET_TSTAMP_H', 1)
  endif

  cdata.set10('HAVE_DECL_SKF_AD_VLAN_TAG_PRESENT',
    cc.has_header_symbol('linux/filter.h', 'SKF_AD_VLAN_TAG_PRESENT'))

  # Netfilter support.
  if cc.compiles('''
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <linux/types.h>
    #include <linux/netlink.h>
    #include <linux/netfilter.h>
    #include <linux/netfilter/nfnetlink.h>
    #include <linux/netfilter/nfnetlink_log.h>
    #include <linux/netfilter/nfnetlink_queue.h>
    int main(void) { return 0; }
  ''', name: 'netfilter support')
    cdata.set('PCAP_SUPPORT_NETFILTER', 1)
    platform_src += files('pcap-netfilter-linux.c')
  endif

  # USB monitoring.
  if get_option('usb').allowed()
    cdata.set('PCAP_SUPPORT_LINUX_USBMON', 1)
    platform_src += files('pcap-usb-linux.c')
    _have_linux_compiler_h = cc.has_header('linux/compiler.h')
    if _have_linux_compiler_h
      cdata.set('HAVE_LINUX_COMPILER_H', 1)
    endif
    _usbdevfs_prefix = ''
    if _have_linux_compiler_h
      _usbdevfs_prefix = '#include <linux/compiler.h>\n'
    endif
    if cc.has_header('linux/usbdevice_fs.h', prefix: _usbdevfs_prefix)
      cdata.set('HAVE_LINUX_USBDEVICE_FS_H', 1)
      if cc.has_member('struct usbdevfs_ctrltransfer', 'bRequestType',
          prefix: _usbdevfs_prefix + '#include <linux/usbdevice_fs.h>')
        cdata.set('HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE', 1)
      endif
    endif
  endif
endif

#
# HP-UX specific.
#
if system == 'hpux'
  if cc.has_member('dl_hp_ppa_info_t', 'dl_module_id_1',
      prefix: '''#include <sys/types.h>
                 #include <sys/dlpi.h>
                 #include <sys/dlpi_ext.h>''')
    cdata.set('HAVE_DL_HP_PPA_INFO_T_DL_MODULE_ID_1', 1)
  endif
  cdata.set('HAVE_HPUX10_20_OR_LATER', 1)
endif

#
# Optional dependencies.
#

# libnl (Linux netlink support).
if system == 'linux' and get_option('libnl').allowed()
  libnl_dep = dependency('libnl-genl-3.0', required: get_option('libnl'))
  if libnl_dep.found()
    cdata.set('HAVE_LIBNL', 1)
    pcap_deps += libnl_dep
    requires_private += 'libnl-genl-3.0'
  endif
endif

# Bluetooth (Linux only).
if system == 'linux' and get_option('bluetooth').allowed()
  if cc.has_header('bluetooth/bluetooth.h')
    cdata.set('PCAP_SUPPORT_BT', 1)
    platform_src += files('pcap-bt-linux.c')
    if cc.has_member('struct sockaddr_hci', 'hci_channel',
        prefix: '#include <bluetooth/bluetooth.h>\n#include <bluetooth/hci.h>')
      cdata.set('HAVE_STRUCT_SOCKADDR_HCI_HCI_CHANNEL', 1)
      if cc.compiles('''
        #include <bluetooth/bluetooth.h>
        #include <bluetooth/hci.h>
        int main(void) { int i = HCI_CHANNEL_MONITOR; return i; }
      ''', name: 'HCI_CHANNEL_MONITOR')
        cdata.set('PCAP_SUPPORT_BT_MONITOR', 1)
        platform_src += files('pcap-bt-monitor-linux.c')
      endif
    endif
  elif get_option('bluetooth').enabled()
    error('Bluetooth support requested but bluetooth/bluetooth.h not found')
  endif
endif

# D-Bus.
if get_option('dbus').allowed()
  if system == 'darwin' and get_option('dbus').enabled()
    error('D-Bus capture support is not available on macOS ' +
          '(freedesktop.org bug 74029)')
  endif
  if system != 'darwin'
    dbus_dep = dependency('dbus-1', required: get_option('dbus'))
    if dbus_dep.found()
      cdata.set('PCAP_SUPPORT_DBUS', 1)
      pcap_deps += dbus_dep
      requires_private += 'dbus-1'
      platform_src += files('pcap-dbus.c')
    endif
  endif
endif

# RDMA (Linux only).
if system == 'linux' and get_option('rdma').allowed()
  libibverbs_dep = dependency('libibverbs', required: get_option('rdma'))
  if libibverbs_dep.found()
    if cc.has_header('infiniband/verbs.h', dependencies: libibverbs_dep) and \
       cc.has_header_symbol('infiniband/verbs.h', 'ibv_create_flow',
          dependencies: libibverbs_dep)
      cdata.set('PCAP_SUPPORT_RDMASNIFF', 1)
      pcap_deps += libibverbs_dep
      requires_private += 'libibverbs'
      platform_src += files('pcap-rdmasniff.c')
    endif
  endif
endif

# Netmap.
if get_option('netmap').allowed()
  if cc.compiles('''
    #define NETMAP_WITH_LIBS
    #include <net/netmap_user.h>
    int main(void) { return 0; }
  ''', name: 'netmap support')
    cdata.set('PCAP_SUPPORT_NETMAP', 1)
    platform_src += files('pcap-netmap.c')
  endif
endif

# DPDK.
if get_option('dpdk').allowed()
  dpdk_dep = dependency('libdpdk', required: get_option('dpdk'))
  if dpdk_dep.found()
    if cc.has_function('rte_eth_dev_count_avail', dependencies: dpdk_dep)
      cdata.set('PCAP_SUPPORT_DPDK', 1)
      pcap_deps += dpdk_dep
      requires_private += 'libdpdk'
      platform_src += files('pcap-dpdk.c')
      if cc.has_type('struct rte_ether_addr',
          prefix: '#include <rte_ether.h>', dependencies: dpdk_dep)
        cdata.set('HAVE_STRUCT_RTE_ETHER_ADDR', 1)
      endif
    endif
  endif
endif

# Remote capture support.
if opt_remote
  platform_src += files('pcap-rpcap.c', 'rpcap-protocol.c', 'sockutils.c')
  if cc.has_member('struct msghdr', 'msg_control',
      prefix: '#include "ftmacros.h"\n#include <sys/socket.h>',
      include_directories: include_directories('.'))
    cdata.set('HAVE_STRUCT_MSGHDR_MSG_CONTROL', 1)
  endif
  if cc.has_member('struct msghdr', 'msg_flags',
      prefix: '#include "ftmacros.h"\n#include <sys/socket.h>',
      include_directories: include_directories('.'))
    cdata.set('HAVE_STRUCT_MSGHDR_MSG_FLAGS', 1)
  endif
  openssl_dep = dependency('openssl', required: false)
  if openssl_dep.found()
    cdata.set('HAVE_OPENSSL', 1)
    pcap_deps += openssl_dep
    requires_private += 'openssl'
    platform_src += files('sslutils.c')
  endif
endif

#
# Flex and Bison.
#
flex = find_program('flex', 'lex', native: true)
bison = find_program('bison', 'byacc', 'yacc', native: true)

# Determine reentrant parser directive. Modern bison (>= 2.4) supports
# %define api.pure; Berkeley YACC and older bison need %pure-parser.
_bison_ver = run_command(bison, '--version', check: false)
if _bison_ver.returncode() == 0 and _bison_ver.stdout().contains('bison')
  reentrant_parser = '%define api.pure'
else
  reentrant_parser = '%pure-parser'
endif

_grammar_y_conf = configuration_data()
_grammar_y_conf.set('REENTRANT_PARSER', reentrant_parser)
grammar_y = configure_file(
  input: 'grammar.y.in',
  output: 'grammar.y',
  configuration: _grammar_y_conf,
)

grammar_ch = custom_target('grammar',
  input: grammar_y,
  output: ['grammar.c', 'grammar.h'],
  command: [bison, '-p', 'pcap_', '-o', '@OUTPUT0@', '-d', '@INPUT@'],
)

scanner_ch = custom_target('scanner',
  input: 'scanner.l',
  output: ['scanner.c', 'scanner.h'],
  command: [flex, '-P', 'pcap_', '--header-file=@OUTPUT1@',
            '--nounput', '-o', '@OUTPUT0@', '@INPUT@'],
)

#
# Generate config.h.
#
config_h = configure_file(output: 'config.h', configuration: cdata)

#
# Compiler flags.
#
pcap_c_args = [
  '-DBUILDING_PCAP',
  '-Dpcap_EXPORTS',
  '-DPCAP_PLUGIN_DIR="@0@"'.format(plugin_dir),
] + extra_cflags

if cc.has_argument('-fvisibility=hidden')
  pcap_c_args += '-fvisibility=hidden'
elif cc.has_argument('-xldscope=hidden')
  # Sun C / Oracle Studio.
  pcap_c_args += '-xldscope=hidden'
endif

if system == 'haiku'
  pcap_c_args += '-D_BSD_SOURCE'
endif
if system == 'sunos'
  pcap_c_args += '-D_TS_ERRNO'
endif

#
# Library target.
#
if system == 'darwin'
  _soversion = 'A'
else
  _soversion = version_major
endif

pcap_lib = library('pcap',
  common_src, platform_src, grammar_ch, scanner_ch, config_h,
  c_args: pcap_c_args,
  dependencies: pcap_deps,
  version: lib_version,
  soversion: _soversion,
  install: not meson.is_subproject(),
)

#
# Dependency object for use as a subproject.
#
pcap_dep = declare_dependency(
  link_with: pcap_lib,
  include_directories: include_directories('.'),
  variables: {'plugindir': plugin_dir},
)
meson.override_dependency('libpcap', pcap_dep)

#
# pkg-config.
#
if not meson.is_subproject()
  pkgconfig.generate(pcap_lib,
    name: 'libpcap',
    description: 'Platform-independent network traffic capture library',
    url: 'https://www.tcpdump.org/',
    requires_private: requires_private,
    libraries_private: pcap_libs_private,
    variables: ['plugindir=' + plugin_dir],
  )
endif

#
# Installation (skip when used as a subproject).
#
if not meson.is_subproject()
  # Public headers.
  install_headers('pcap.h', 'pcap-bpf.h', 'pcap-namedb.h')
  install_headers(
    'pcap/bluetooth.h',
    'pcap/bpf.h',
    'pcap/can_socketcan.h',
    'pcap/compiler-tests.h',
    'pcap/dlt.h',
    'pcap/funcattrs.h',
    'pcap/ipnet.h',
    'pcap/namedb.h',
    'pcap/nflog.h',
    'pcap/pcap-inttypes.h',
    'pcap/pcap.h',
    'pcap/pcap-plugin.h',
    'pcap/sll.h',
    'pcap/socket.h',
    'pcap/usb.h',
    'pcap/vlan.h',
    subdir: 'pcap',
  )

  # pcap-config script.
  _pcap_config_data = configuration_data()
  _pcap_config_data.set('prefix', get_option('prefix'))
  _pcap_config_data.set('exec_prefix', '${prefix}')
  _pcap_config_data.set('includedir', '${prefix}/' + get_option('includedir'))
  _pcap_config_data.set('libdir', '${exec_prefix}/' + get_option('libdir'))
  _pcap_config_data.set('LIBS', ' '.join(pcap_libs_private))
  _pcap_config_data.set('LIBS_STATIC', ' '.join(pcap_libs_private))
  _pcap_config_data.set('PACKAGE_VERSION', version)
  _pcap_config_data.set('PACKAGE_NAME', 'pcap')
  _pcap_config_data.set('RPATH', '')
  configure_file(
    input: 'pcap-config.in',
    output: 'pcap-config',
    configuration: _pcap_config_data,
    install: true,
    install_dir: get_option('bindir'),
    install_mode: 'rwxr-xr-x',
  )

  # Man page section numbers (V7/BSD convention by default).
  _man_file_formats = '5'
  _man_misc_info = '7'
  _man_admin_commands = '8'
  if system == 'sunos' or system == 'hpux'
    _man_file_formats = '4'
    _man_misc_info = '5'
    _man_admin_commands = '1m'
  endif

  # V7/BSD: devices in section 4.
  _man_devices = '4'
  if system == 'sunos'
    _man_devices = '7D'
  endif

  _man_conf = configuration_data()
  _man_conf.set('MAN_DEVICES', _man_devices)
  _man_conf.set('MAN_FILE_FORMATS', _man_file_formats)
  _man_conf.set('MAN_MISC_INFO', _man_misc_info)
  _man_conf.set('MAN_ADMIN_COMMANDS', _man_admin_commands)

  # Man section 1.
  install_data('pcap-config.1',
    install_dir: get_option('mandir') / 'man1')

  # Man section 3 - pages that need template expansion.
  _man3_expand = [
    'pcap.3pcap.in',
    'pcap_compile.3pcap.in',
    'pcap_datalink.3pcap.in',
    'pcap_dump_open.3pcap.in',
    'pcap_get_tstamp_precision.3pcap.in',
    'pcap_list_datalinks.3pcap.in',
    'pcap_list_tstamp_types.3pcap.in',
    'pcap_open_dead.3pcap.in',
    'pcap_open_offline.3pcap.in',
    'pcap_set_immediate_mode.3pcap.in',
    'pcap_set_tstamp_precision.3pcap.in',
    'pcap_set_tstamp_type.3pcap.in',
  ]
  foreach _m : _man3_expand
    _out = _m.replace('.in', '')
    configure_file(
      input: _m,
      output: _out,
      configuration: _man_conf,
      install: true,
      install_dir: get_option('mandir') / 'man3',
    )
  endforeach

  # Man section 3 - pages without expansion.
  _man3_noexpand = [
    'pcap_activate.3pcap',
    'pcap_breakloop.3pcap',
    'pcap_can_set_rfmon.3pcap',
    'pcap_close.3pcap',
    'pcap_create.3pcap',
    'pcap_datalink_name_to_val.3pcap',
    'pcap_datalink_val_to_name.3pcap',
    'pcap_dump.3pcap',
    'pcap_dump_close.3pcap',
    'pcap_dump_file.3pcap',
    'pcap_dump_flush.3pcap',
    'pcap_dump_ftell.3pcap',
    'pcap_file.3pcap',
    'pcap_fileno.3pcap',
    'pcap_findalldevs.3pcap',
    'pcap_freecode.3pcap',
    'pcap_get_required_select_timeout.3pcap',
    'pcap_get_selectable_fd.3pcap',
    'pcap_geterr.3pcap',
    'pcap_init.3pcap',
    'pcap_inject.3pcap',
    'pcap_is_swapped.3pcap',
    'pcap_lib_version.3pcap',
    'pcap_lookupdev.3pcap',
    'pcap_lookupnet.3pcap',
    'pcap_loop.3pcap',
    'pcap_major_version.3pcap',
    'pcap_next_ex.3pcap',
    'pcap_offline_filter.3pcap',
    'pcap_open_live.3pcap',
    'pcap_set_buffer_size.3pcap',
    'pcap_set_datalink.3pcap',
    'pcap_set_promisc.3pcap',
    'pcap_set_protocol_linux.3pcap',
    'pcap_set_rfmon.3pcap',
    'pcap_set_snaplen.3pcap',
    'pcap_set_timeout.3pcap',
    'pcap_setdirection.3pcap',
    'pcap_setfilter.3pcap',
    'pcap_setnonblock.3pcap',
    'pcap_snapshot.3pcap',
    'pcap_stats.3pcap',
    'pcap_statustostr.3pcap',
    'pcap_strerror.3pcap',
    'pcap_tstamp_type_name_to_val.3pcap',
    'pcap_tstamp_type_val_to_name.3pcap',
  ]
  install_data(_man3_noexpand,
    install_dir: get_option('mandir') / 'man3')

  # Man section 3 symlinks.
  _man3_symlinks = {
    'pcap_datalink_val_to_description.3pcap': 'pcap_datalink_val_to_name.3pcap',
    'pcap_datalink_val_to_description_or_dlt.3pcap': 'pcap_datalink_val_to_name.3pcap',
    'pcap_dump_fopen.3pcap': 'pcap_dump_open.3pcap',
    'pcap_freealldevs.3pcap': 'pcap_findalldevs.3pcap',
    'pcap_perror.3pcap': 'pcap_geterr.3pcap',
    'pcap_sendpacket.3pcap': 'pcap_inject.3pcap',
    'pcap_free_datalinks.3pcap': 'pcap_list_datalinks.3pcap',
    'pcap_free_tstamp_types.3pcap': 'pcap_list_tstamp_types.3pcap',
    'pcap_dispatch.3pcap': 'pcap_loop.3pcap',
    'pcap_minor_version.3pcap': 'pcap_major_version.3pcap',
    'pcap_next.3pcap': 'pcap_next_ex.3pcap',
    'pcap_open_dead_with_tstamp_precision.3pcap': 'pcap_open_dead.3pcap',
    'pcap_open_offline_with_tstamp_precision.3pcap': 'pcap_open_offline.3pcap',
    'pcap_fopen_offline.3pcap': 'pcap_open_offline.3pcap',
    'pcap_fopen_offline_with_tstamp_precision.3pcap': 'pcap_open_offline.3pcap',
    'pcap_tstamp_type_val_to_description.3pcap': 'pcap_tstamp_type_val_to_name.3pcap',
    'pcap_getnonblock.3pcap': 'pcap_setnonblock.3pcap',
  }
  foreach link_name, target : _man3_symlinks
    install_symlink(link_name,
      pointing_to: target,
      install_dir: get_option('mandir') / 'man3',
    )
  endforeach

  # Man file-formats section.
  _manfile_expand = ['pcap-savefile.manfile.in']
  foreach _m : _manfile_expand
    _out = _m.replace('.manfile.in', '.' + _man_file_formats)
    configure_file(
      input: _m,
      output: _out,
      configuration: _man_conf,
      install: true,
      install_dir: get_option('mandir') / 'man' + _man_file_formats,
    )
  endforeach

  # Man misc-info section.
  _manmisc_expand = [
    'pcap-filter.manmisc.in',
    'pcap-linktype.manmisc.in',
    'pcap-tstamp.manmisc.in',
  ]
  foreach _m : _manmisc_expand
    _out = _m.replace('.manmisc.in', '.' + _man_misc_info)
    configure_file(
      input: _m,
      output: _out,
      configuration: _man_conf,
      install: true,
      install_dir: get_option('mandir') / 'man' + _man_misc_info,
    )
  endforeach
endif
