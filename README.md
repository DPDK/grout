# grout # a graph router based on DPDK

![logo.svg](https://raw.githubusercontent.com/DPDK/grout/main/docs/logo.svg)

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

[BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html)

## Features

* IPv4 forwarding
* IPv6 forwarding
* Multiple VRF domains
* VLAN sub interfaces
* IP in IP tunnels

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
add interface port p0 devargs 0000:8a:00.0 rxqs 1 qsize 2048
add interface port p1 devargs 0000:8a:00.1 rxqs 1 qsize 2048
# remap rxqs to isolated cpus
set port qmap p0 rxq 0 cpu 2
set port qmap p1 rxq 0 cpu 22
add ip address 1.2.3.4/24 iface p0
add ip address 4.3.2.1/24 iface p1
add ip route 0.0.0.0/0 via 1.2.3.254
EOF

systemctl restart grout.service
```

```console
[root@grout]$ systemctl status -n40 grout.service
● grout.service - Graph router daemon
     Loaded: loaded (/usr/lib/systemd/system/grout.service; enabled; preset: disabled)
     Active: active (running) since Mon 2024-09-09 10:31:40 CEST; 4s ago
    Process: 31298 ExecStartPre=/usr/bin/udevadm settle (code=exited, status=0/SUCCESS)
    Process: 31302 ExecStartPost=/usr/bin/grcli -xef /etc/grout.init (code=exited, status=0/SUCCESS)
   Main PID: 31299 (grout)
     Status: "grout version v0.1-108-gb46a80db started"
      Tasks: 5 (limit: 195427)
     Memory: 6.6M
        CPU: 19.185s
     CGroup: /system.slice/grout.service
             └─31299 /usr/sbin/grout

Sep 09 10:31:31 grout systemd[1]: Starting Graph router daemon...
Sep 09 10:31:31 grout grout[31299]: GROUT: main: starting grout version v0.1-108-gb46a80db
Sep 09 10:31:31 grout grout[31299]: GROUT: dpdk_init: DPDK 24.07.0
Sep 09 10:31:31 grout grcli[31302]: + add interface port p0 devargs 0000:8a:00.0 rxqs 1 qsize 2048
Sep 09 10:31:32 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 1] starting tid=31303
Sep 09 10:31:40 grout grcli[31302]: Created interface 1
Sep 09 10:31:32 grout grcli[31302]: + add interface port p1 devargs 0000:8a:00.1 rxqs 1 qsize 2048
Sep 09 10:31:40 grout grcli[31302]: Created interface 2
Sep 09 10:31:33 grout grcli[31302]: + set port qmap p0 rxq 0 cpu 2
Sep 09 10:31:33 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 2] starting tid=31304
Sep 09 10:31:38 grout grcli[31302]: + set port qmap p1 rxq 0 cpu 22
Sep 09 10:31:38 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 22] starting tid=31305
Sep 09 10:31:38 grout grout[31299]: GROUT: gr_datapath_loop: [CPU 1] shutting down tid=31303
Sep 09 10:31:40 grout grcli[31302]: + add ip address 172.16.0.2/24 iface p0
Sep 09 10:31:40 grout grcli[31302]: + add ip address 172.16.1.2/24 iface p1
Sep 09 10:31:40 grout grcli[31302]: + add ip route 0.0.0.0/0 via 172.16.1.183
Sep 09 10:31:40 grout systemd[1]: Started Graph router daemon.
```

### Interact with the CLI

By default, the CLI will start an interactive shell with command completion:

```console
[root@grout]$ grcli
Welcome to the grout CLI.
Use ? for help and <tab> for command completion.
grout# ?
quit                 Exit the CLI.
add                  Create objects in the configuration.
del                  Delete objects from the configuration.
show                 Display information about the configuration.
clear                Clear counters or temporary entries.
set                  Modify existing objects in the configuration.
grout# show interface all
NAME  ID  FLAGS       VRF  TYPE  INFO
p0    1   up running  0    port  devargs=0000:8a:00.0 mac=30:3e:a7:0b:eb:c0
p1    2   up running  0    port  devargs=0000:8a:00.1 mac=30:3e:a7:0b:eb:c1
grout# show port qmap
IFACE  RXQ_ID  CPU_ID  ENABLED
p0     0       2       1
p1     0       22      1
grout# show ip address
IFACE  ADDRESS
p0     172.16.0.2/24
p1     172.16.1.2/24
grout# show ip route
DESTINATION    NEXT_HOP
172.16.0.0/24  172.16.0.2
172.16.1.0/24  172.16.1.2
0.0.0.0/0      172.16.1.183
grout# show ip nexthop
VRF  IP            MAC                IFACE  QUEUE  AGE  STATE
0    172.16.0.2    30:3e:a7:0b:eb:c0  p0     0      0    reachable static local link
0    172.16.1.2    30:3e:a7:0b:eb:c1  p1     0      0    reachable static local link
0    172.16.1.183  ??:??:??:??:??:??  ?      0      ?    gateway
grout#

```

The CLI can also be used as a one-shot command (bash-completion is available):

```console
[root@grout]$ grcli <TAB><TAB>
add                 (Create objects in the configuration.)
clear               (Clear counters or temporary entries.)
del                 (Delete objects from the configuration.)
-e                  (Abort on first error.)
--err-exit          (Abort on first error.)
--help              (Show usage help and exit.)
-h                  (Show usage help and exit.)
quit                (Exit the CLI.)
set                 (Modify existing objects in the configuration.)
show                (Display information about the configuration.)
--socket            (Path to the control plane API socket.)
-s                  (Path to the control plane API socket.)
--trace-commands    (Print executed commands.)
-x                  (Print executed commands.)
[root@grout]$ grcli show <TAB><TAB>
graph        (Show packet processing graph info.)
interface    (Display interface details.)
ip           (Show IPv4 stack details.)
port         (Display DPDK port information.)
stats        (Print statistics.)
[root@grout]$ grcli show stats <TAB><TAB>
hardware    (Print hardware stats.)
software    (Print software stats.)
[root@grout]$ grcli show stats software
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
[root@grout]$ grcli show graph dot | grep -vE 'darkorange|error' | dot -Tsvg > docs/graph.svg
```

![docs/graph.svg](https://raw.githubusercontent.com/DPDK/grout/main/docs/graph.svg)

## Build from source

### Install build dependencies

```sh
dnf install gcc git make meson ninja-build pkgconf scdoc python3-pyelftools \
        libcmocka-devel libedit-devel libevent-devel numactl-devel \
        libsmartcols-devel libarchive-devel rdma-core-devel \
        clang-tools-extra jq curl traceroute
```

or

```sh
apt install git gcc make meson ninja-build pkgconf scdoc python3-pyelftools \
        libcmocka-dev libedit-dev libevent-dev libnuma-dev \
        libsmartcols-dev libarchive-dev libibverbs-dev \
        clang-format jq curl traceroute
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
[root@dev grout]$ taskset --cpu-list 0,2,22 ./build/grout -v -s grout.sock
INFO: GROUT: dpdk_init: starting grout version v0.1-103.g39e42d1e
INFO: GROUT: dpdk_init: DPDK 24.07.0
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

## Contributing

Anyone can contribute to `grout`. See
[`CONTRIBUTING.md`](https://github.com/DPDK/grout/blob/main/CONTRIBUTING.md).

## Dependencies

| Name | Type | License | Code |
|------|------|---------|------|
| DPDK | Build & Runtime | BSD-3-Clause | https://git.dpdk.org/dpdk/ |
| libnuma | Build & Runtime | LGPL-2.1 | https://github.com/numactl/numactl |
| libevent | Build & Runtime | BSD-3-Clause | https://github.com/libevent/libevent |
| libstb | Build & Runtime | Public Domain | https://github.com/nothings/stb |
| libecoli | Build & Runtime | BSD-3-Clause | https://git.sr.ht/~rjarry/libecoli |
| libsmartcols | Build & Runtime | LGPL-2.1 | https://github.com/util-linux/util-linux/tree/master/libsmartcols |
| cmocka | Build | Apache-2.0 | https://github.com/clibs/cmocka |
| meson | Build | Apache-2.0 | https://github.com/mesonbuild/meson |
| ninja | Build | Apache-2.0 | https://github.com/ninja-build/ninja |
| libasan | Dev | MIT+BSD | https://github.com/gcc-mirror/gcc/tree/master/libsanitizer |
| clang-format | Dev | MIT+BSD | https://clang.llvm.org/docs/ClangFormat.html |
