# grout # a graph router based on DPDK

![logo.svg](/docs/logo.svg)

`grout` stands for *Graph Router*. In English, *"grout"* refers to thin mortar
that hardens to fill gaps between tiles.

`grout` is a DPDK based network processing application. It uses the [rte_graph]
library for data path processing.

Its main purpose is to simulate a network function or a physical router for
testing/replicating real (usually closed source) VNF/CNF behavior with an
opensource tool.

It comes with a client library to configure it over a standard UNIX socket and
a CLI that uses that library. The CLI can be used as an interactive shell, but
also in scripts one command at a time, or by batches.

[rte_graph]: http://doc.dpdk.org/guides/prog_guide/graph_lib.html

## License

* [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html)
* [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) — only
  for the `frr` plugin.

## Features

* IPv4 forwarding
* IPv6 forwarding
* Multiple VRF domains
* VLAN sub interfaces
* IP in IP tunnels
* SRv6
* Static IPv4 DNAT
* Dynamic IPv4 SNAT (with connection tracking)
* FRR synchronization via a [dplane plugin](/frr)

## Quickstart

### Installation

Some nightly packages are available in the [edge] release. For quick
installation on RPM and DEB based distributions.

[edge]: https://github.com/DPDK/grout/releases/tag/edge

Example:

```sh
dnf install https://github.com/DPDK/grout/releases/download/edge/grout.x86_64.rpm
```

or

```sh
wget https://github.com/DPDK/grout/releases/download/edge/grout_amd64.deb
apt install ./grout_amd64.deb
```

### Host configuration

Once the package and its dependencies are installed, you need to ensure your
machine is setup properly to run DPDK applications.

Example on Intel RHEL/CentOS/Fedora:

```sh
dnf install driverctl tuned-profiles-cpu-partitioning

# Enable IOMMU on boot.
grubby --update-kernel ALL --args "iommu=pt intel_iommu=on"

# Reserve hugepages.
grubby --update-kernel ALL --args "default_hugepagesz=1GB hugepagesz=1G hugepages=16"

# Isolate CPUs for grout datapath (adjust to taste).
echo "isolated_cores=2-19,22-39" > /etc/tuned/cpu-partitioning-powersave-variables.conf
echo "max_power_state=C6|170" >> /etc/tuned/cpu-partitioning-powersave-variables.conf
tuned-adm profile cpu-partitioning-powersave
grubby --update-kernel ALL --args "isolcpus=2-19,22-39"

# Reboot to enable IOMMU and have hugepages reserved.
systemctl reboot

# Bind the devices you intend on using with grout to vfio-pci.
# NB: NVIDIA/Mellanox NICs should remain bound to their default driver.
driverctl set-override 0000:8a:00.0 vfio-pci
driverctl set-override 0000:8a:00.1 vfio-pci
```

See DPDK documentation for more details:

* https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#running-dpdk-applications
* https://doc.dpdk.org/guides/linux_gsg/enable_func.html#using-linux-core-isolation-to-reduce-context-switches

### (Re)Start the service

```sh
# Startup configuration.
cat > /etc/grout.init <<EOF
affinity cpus set control 0,1,20,21 datapath 2,22
interface add port p0 devargs 0000:8a:00.0 rxqs 1 qsize 2048
interface add port p1 devargs 0000:8a:00.1 rxqs 1 qsize 2048
address add 1.2.3.4/24 iface p0
address add 4.3.2.1/24 iface p1
route add 0.0.0.0/0 via 1.2.3.254
EOF

systemctl restart grout.service
```

```console
[root@grout]$ systemctl status -n40 grout.service
● grout.service - Graph router daemon
     Loaded: loaded (/usr/lib/systemd/system/grout.service; enabled; preset: disabled)
     Active: active (running) since Sat 2024-11-30 10:31:40 CEST; 4s ago
    Process: 31298 ExecStartPre=/usr/bin/udevadm settle (code=exited, status=0/SUCCESS)
    Process: 31302 ExecStartPost=/usr/bin/grcli -xef /etc/grout.init (code=exited, status=0/SUCCESS)
   Main PID: 31299 (grout)
     Status: "grout version v0.2-93-gf53240e3750a started"
      Tasks: 5 (limit: 195427)
     Memory: 6.6M
        CPU: 19.185s
     CGroup: /system.slice/grout.service
             └─31299 /usr/bin/grout

Nov 30 10:31:31 grout systemd[1]: Starting Graph router daemon...
Nov 30 10:31:31 grout grout[31299]: GROUT: main: starting grout version v0.2-93-gf53240e3750a
Nov 30 10:31:31 grout grout[31299]: GROUT: dpdk_init: DPDK 24.11.0
Nov 30 10:31:31 grout grcli[31302]: + interface add port p0 devargs 0000:8a:00.0 rxqs 1 qsize 2048
Nov 30 10:31:32 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 2] starting tid=31303
Nov 30 10:31:40 grout grcli[31302]: Created interface 1
Nov 30 10:31:32 grout grcli[31302]: + interface add port p1 devargs 0000:8a:00.1 rxqs 1 qsize 2048
Nov 30 10:31:34 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 22] starting tid=31305
Nov 30 10:31:40 grout grcli[31302]: Created interface 2
Nov 30 10:31:40 grout grcli[31302]: + address add 172.16.0.2/24 iface p0
Nov 30 10:31:40 grout grcli[31302]: + address add 172.16.1.2/24 iface p1
Nov 30 10:31:40 grout grcli[31302]: + route add 0.0.0.0/0 via 172.16.1.183
Nov 30 10:31:40 grout systemd[1]: Started Graph router daemon.
```

### Interact with the CLI

By default, the CLI will start an interactive shell with command completion:

```console
[root@grout]$ grcli
Welcome to the grout CLI.
Use ? for help and <tab> for command completion.
grout# ?
address              IP addresses.
affinity             CPU and physical queue affinity.
conntrack            Connection tracking.
dnat44               Static destination NAT44.
events               Subscribe to all events and dump them in real time
graph                Show packet processing graph info (requires interfaces to be configured).
interface            Interfaces.
logging              Ingress/egress packet logging.
nexthop              Nexthops.
ping                 Send ICMPv6 echo requests and wait for replies.
quit                 Exit the CLI.
route                Routing tables.
router-advert        IPv6 router advertisements.
snat44               Dynamic source NAT44.
stats                Packet processing statistics.
trace                Packet tracing.
traceroute           Discover IPv6 intermediate gateways.
tunsrc               SRv6 source address.
grout# interface show
NAME  ID   FLAGS       MODE  DOMAIN  TYPE  INFO
p0    256  up running  L3    0       port  devargs=0000:8a:00.0 mac=30:3e:a7:0b:eb:c0
p1    257  up running  L3    0       port  devargs=0000:8a:00.1 mac=30:3e:a7:0b:eb:c1
grout# affinity qmap show
IFACE  RXQ_ID  CPU_ID  ENABLED
p0     0       2       1
p1     0       22      1
grout# address show
IFACE  ADDRESS
p0     172.16.0.2/24
p1     172.16.1.2/24
grout# route show
VRF  DESTINATION    NEXT_HOP
0    172.16.0.0/24  type=L3 iface=p0 vrf=0 origin=link af=IPv4 addr=172.16.0.2/24 mac=22:43:d9:2d:dd:58 static local gateway link
0    172.16.1.0/24  type=L3 iface=p1 vrf=0 origin=link af=IPv4 addr=172.16.1.2/24 mac=1e:34:18:0e:a8:38 static local gateway link
0    0.0.0.0/0      type=L3 id=1 iface=p1 vrf=0 origin=user af=IPv4 addr=172.16.1.183 state=new gateway
grout# nexthop show
VRF  ID  ORIGIN  IFACE  TYPE  INFO
0        link    p0     L3    af=IPv6 addr=fe80::2243:d9ff:fe2d:dd58/64 mac=22:43:d9:2d:dd:58 static local gateway link
0        link    p1     L3    af=IPv6 addr=fe80::1e34:18ff:fe0e:a838/64 mac=1e:34:18:0e:a8:38 static local gateway link
0        link    p0     L3    af=IPv4 addr=172.16.0.2/24 mac=22:43:d9:2d:dd:58 static local gateway link
0        link    p1     L3    af=IPv4 addr=172.16.1.2/24 mac=1e:34:18:0e:a8:38 static local gateway link
0    1   user    p1     L3    af=IPv4 addr=172.16.1.183 state=new gateway
grout#

```

The CLI can also be used as a one-shot command (bash-completion is available):

```console
[root@grout]$ grcli <TAB><TAB>
address             (IP addresses.)
affinity            (CPU and physical queue affinity.)
conntrack           (Connection tracking.)
dnat44              (Static destination NAT44.)
-e                  (Abort on first error.)
--err-exit          (Abort on first error.)
events              (Subscribe to all events and dump them in real time)
graph               (Show packet processing graph info (requires interfaces to be configured).)
--help              (Show usage help and exit.)
-h                  (Show usage help and exit.)
interface           (Interfaces.)
logging             (Ingress/egress packet logging.)
nexthop             (Nexthops.)
ping                (Send ICMPv6 echo requests and wait for replies.)
quit                (Exit the CLI.)
route               (Routing tables.)
router-advert       (IPv6 router advertisements.)
snat44              (Dynamic source NAT44.)
--socket            (Path to the control plane API socket.)
-s                  (Path to the control plane API socket.)
stats               (Packet processing statistics.)
--trace-commands    (Print executed commands.)
trace               (Packet tracing.)
traceroute          (Discover IPv6 intermediate gateways.)
tunsrc              (SRv6 source address.)
-x                  (Print executed commands.)
[root@grout]$ grcli stats <TAB><TAB>
reset       (Reset all stats to zero.)
show        (Print statistics.)
[root@grout]$ grcli stats show <TAB><TAB>
hardware    (Print hardware stats.)
software    (Print software stats.)
[root@grout]$ grcli stats show software
NODE         CALLS   PACKETS  PKTS/CALL  CYCLES/CALL  CYCLES/PKT
port_rx     757792  22623757       29.9       1776.4        59.5
ip_input    333675  22623757       67.8       3091.0        45.6
port_tx     333675  22623757       67.8       1984.2        29.3
eth_input   757792  22623757       29.9        659.7        22.1
eth_output  333675  22623757       67.8       1323.4        19.5
ip_output   333675  22623757       67.8        926.3        13.7
ip_forward  333675  22623757       67.8        691.8        10.2
```

## Packet graph

Dump the packet graph (excluding all error nodes) and convert it to an SVG
image.

```console
[root@grout]$ grcli graph brief | dot -Tsvg > docs/graph.svg
```

![docs/graph.svg](/docs/graph.svg)

## Build from source

### Install build dependencies

```sh
dnf install git gcc make meson ninja-build pkgconf \
        python3-pyelftools golang-github-cpuguy83-md2man \
        libcmocka-devel libedit-devel libevent-devel numactl-devel \
        libsmartcols-devel libarchive-devel rdma-core-devel
```

or

```sh
apt install git gcc make meson ninja-build pkgconf \
        python3-pyelftools go-md2man \
        libcmocka-dev libedit-dev libevent-dev libnuma-dev \
        libsmartcols-dev libarchive-dev libibverbs-dev
```

Important: `grout` requires at least `gcc` 13 or `clang` 15.

### Install development dependencies

In order to run the `smoke-tests`, `lint`, `check-patches` and `update-graph`
targets, you'll need additional packages:

```sh
dnf install gawk gdb clang-tools-extra jq codespell curl traceroute graphviz ndisc6
```

or

```sh
apt install gawk gdb clang-format jq codespell curl traceroute graphviz ndisc6
```

### Build

```
git clone https://github.com/DPDK/grout
cd grout
make
```

### Start the router daemon

The binaries are located in the build directory:

```console
[root@dev grout]$ ./build/grout -v -s grout.sock
INFO: GROUT: dpdk_init: starting grout version v0.2-93-gf53240e3750a
INFO: GROUT: dpdk_init: DPDK 24.11.0
INFO: GROUT: dpdk_init: EAL arguments: -l 0 -a 0000:00:00.0 --log-level=*:notice --log-level=grout:info
...
INFO: GROUT: listen_api_socket: listening on API socket grout.sock
```

### Start the CLI

```console
[root@dev grout]$ ./build/grcli -s grout.sock
Welcome to the grout CLI.
Use ? for help and <tab> for command completion.
grout#
```

### Debugging tools

Pretty printers for Grout are available in `devtools/gdb_pprint.py`.

To automatically load them, a `.gdbinit` file is provided, that you can enable
by adding the following to your `$HOME/.gdbinit` file:

```
set auto-load local-gdbinit on
set auto-load safe-path /
```

You can also load the python script manually:

```
(gdb) source devtools/gdb_pprint.py
```

Multiple pretty printers are available, you can verify they are loaded with
`info pretty-printer`:

```
(gdb) info pretty-printer
global pretty-printers:
  builtin
    mpx_bound128
  grout
    ip4_addr_t
    struct iface
    struct rte_ether_addr
    struct rte_ipv6_addr
```

## Contact

* Mailing list: grout@dpdk.org ([archives](http://mails.dpdk.org/archives/grout/))
* Slack channel: [#grout @ dpdkproject.slack.com](https://dpdkproject.slack.com/archives/C07NAFWE1MG)

## Contributing

Anyone can contribute to `grout`. See [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## Dependencies

| Name | Type | License | Code |
|------|------|---------|------|
| DPDK | Build & Runtime | BSD-3-Clause | https://git.dpdk.org/dpdk/ |
| libnuma | Build & Runtime | LGPL-2.1 | https://github.com/numactl/numactl |
| libevent | Build & Runtime | BSD-3-Clause | https://github.com/libevent/libevent |
| libecoli | Build & Runtime | BSD-3-Clause | https://git.sr.ht/~rjarry/libecoli |
| libsmartcols | Build & Runtime | LGPL-2.1 | https://github.com/util-linux/util-linux/tree/master/libsmartcols |
| cmocka | Build | Apache-2.0 | https://github.com/clibs/cmocka |
| meson | Build | Apache-2.0 | https://github.com/mesonbuild/meson |
| ninja | Build | Apache-2.0 | https://github.com/ninja-build/ninja |
| go-md2man | Build | MIT | https://github.com/cpuguy83/go-md2man |
| libasan | Dev | MIT+BSD | https://github.com/gcc-mirror/gcc/tree/master/libsanitizer |
| clang-format | Dev | MIT+BSD | https://clang.llvm.org/docs/ClangFormat.html |

Optional (compiled with `-Dfrr=enabled`):

| Name | Type | License | Code |
|------|------|---------|------|
| FRR  | Build & Runtime | GPL-2.0-or-later | https://github.com/FRRouting/frr |
