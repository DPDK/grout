# grout # a graph router based on DPDK

`grout` is a DPDK based network processing application. It uses the `rte_graph`
library for data path processing.

It comes with a client library to configure it over a standard UNIX socket and
a CLI that uses that library. The CLI can be used as an interactive shell, but
also in scripts one command at a time, or by batches.

## Quick start

### Install system dependencies

```sh
dnf install gcc git libcmocka-devel libedit-devel libevent-devel make meson \
        ninja-build numactl-devel pkgconf python3-pyelftools scdoc \
        libsmartcols-devel
```

or

```sh
apt install build-essential gcovr libcmocka-dev libedit-dev libevent-dev \
        libnuma-dev meson ninja-build pkg-config python3-pyelftools scdoc \
        libsmartcols-dev
```

### Build

```
git clone https://github.com/rjarry/grout
cd grout
make
```

### Start the router daemon

```console
[root@dio grout]$ taskset --cpu-list 6-19,26-39 ./build/grout -v
GR: dpdk_init: DPDK 24.03.0
GR: dpdk_init: EAL arguments: -l 0 -a 0000:00:00.0 --log-level=*:notice --log-level=gr:info
EAL: Detected CPU lcores: 40
EAL: Detected NUMA nodes: 1
...
GROUT: listen_api_socket: listening on API socket /run/grout.sock
```

### Start the CLI

By default, the CLI will start an interactive shell with command completion:

```console
[root@dio grout]$ ./build/grcli
Welcome to the grout CLI.
Use ? for help and <tab> for command completion.
grout# ?
quit                 Exit the CLI.
add                  Create objects in the configuration.
del                  Delete objects from the configuration.
show                 Display information about the configuration.
clear                Clear counters or temporary entries.
set                  Modify existing objects in the configuration.
```

Multiple commands can be piped into standard input:

```console
[root@dio grout]$ ./build/grcli -ex < commands.list
+ add interface port p0 devargs 0000:18:00.0 rxqs 1 qsize 2048
Created interface 0
+ add interface port p1 devargs 0000:18:00.1 rxqs 1 qsize 2048
Created interface 1
+ set port qmap p0 rxq 0 cpu 7
+ set port qmap p1 rxq 0 cpu 27
+ show interface all
NAME  ID  FLAGS       TYPE  INFO
p0    0   up running  port  devargs=0000:18:00.0 mac=b8:3f:d2:fa:53:86
p1    1   up running  port  devargs=0000:18:00.1 mac=b8:3f:d2:fa:53:87
+ show port qmap
IFACE  RXQ_ID  CPU_ID  ENABLED
p0     0       7       1
p1     0       27      1
+ add ip address 172.16.0.2/32 iface p0
+ add ip address 172.16.1.2/32 iface p1
+ add ip nexthop 172.16.0.1 mac b8:3f:d2:fa:53:7a iface p0
+ add ip nexthop 172.16.1.1 mac b8:3f:d2:fa:53:7b iface p1
+ add ip route 172.16.0.0/24 via 172.16.0.1
+ add ip route 172.16.1.0/24 via 172.16.1.1
+ add ip route 0.0.0.0/0 via 172.16.1.183
+ show ip address
IFACE  ADDRESS
p0     172.16.0.2/32
p1     172.16.1.2/32
+ show ip route
DESTINATION    NEXT_HOP
172.16.0.1/32  172.16.0.1
172.16.0.2/32  172.16.0.2
172.16.0.0/24  172.16.0.1
172.16.1.1/32  172.16.1.1
172.16.1.2/32  172.16.1.2
172.16.1.0/24  172.16.1.1
0.0.0.0/0      172.16.1.183
+ show ip nexthop
IP            MAC                IFACE  AGE  STATE
172.16.1.183  ??:??:??:??:??:??  ?      ?    gateway
172.16.1.2    b8:3f:d2:fa:53:87  p1     0    reachable static local link
172.16.0.2    b8:3f:d2:fa:53:86  p0     0    reachable static local link
172.16.0.1    b8:3f:d2:fa:53:7a  p0     0    reachable static gateway
172.16.1.1    b8:3f:d2:fa:53:7b  p1     0    reachable static gateway
```

The CLI can be used as a one-shot command (with bash completion built-in):

```console
[root@dio grout]$ complete -o default -C './build/grcli -c' ./build/grcli
[root@dio grout]$ ./build/grcli <TAB><TAB>
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
[root@dio grout]$ ./build/grcli show <TAB><TAB>
graph        (Show packet processing graph info.)
interface    (Display interface details.)
ip           (Show IPv4 stack details.)
port         (Display DPDK port information.)
stats        (Print statistics.)
[root@dio grout]$ ./build/grcli show stats <TAB><TAB>
hardware    (Print hardware stats.)
software    (Print software stats.)
[root@dio grout]$ ./build/grcli show stats software
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

```console
[root@dio grout]$ ./build/grcli show graph dot | dot -Tsvg > docs/graph.svg
```

![docs/graph.svg](https://raw.githubusercontent.com/rjarry/grout/main/docs/graph.svg)

## License

BSD 3 clause.
