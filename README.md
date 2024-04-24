# Boring Router: a sample router based on DPDK

`brouter` stands for *Boring Router*. *Boring* because it should work in all
circumstances, without any fuss nor extended configuration/tuning.

*Boring Router* is a DPDK based network processing application. It uses the
`rte_graph` library for data path processing.

It comes with a client library to configure it over a standard UNIX socket and
a CLI that uses that library. The CLI can be used as an interactive shell, but
also in scripts one command at a time, or by batches.

## Quick start

### Install system dependencies

```sh
dnf install gcc git libcmocka-devel libedit-devel libevent-devel make meson \
        ninja-build numactl-devel pkgconf python3-pyelftools scdoc
```

or

```sh
apt install build-essential gcovr libcmocka-dev libedit-dev libevent-dev \
        libnuma-dev meson ninja-build pkg-config python3-pyelftools scdoc
```

### Build

```
git clone https://github.com/rjarry/brouter
cd brouter
make
```

### Start the router

```console
[root@dio brouter]$ taskset --cpu-list 6-19,26-39 ./build/br -v
BR: dpdk_init: DPDK version: DPDK 23.11.0
BR: dpdk_init: EAL arguments: -l 6 -a 0000:00:00.0 --in-memory --log-level=*:info
EAL: Detected CPU lcores: 40
EAL: Detected NUMA nodes: 1
...
BR: listen_api_socket: listening on API socket /run/br.sock
```

### Start the CLI

By default, the CLI will start an interactive shell with command completion:

```console
[root@dio brouter]$  ./build/br-cli
Welcome to the boring router CLI.
Use ? for help and <tab> for command completion.
br# ?
quit                 Exit the CLI.
add                  Create objects in the configuration.
del                  Delete objects from the configuration.
show                 Display information about the configuration.
clear                Clear counters or temporary entries.
set                  Modify existing objects in the configuration.
```

Multiple commands can be piped into standard input:

```console
[root@dio brouter]$ ./build/br-cli -ex < commands.list
+ add port devargs 0000:18:00.0
Created port 0
+ add port devargs 0000:18:00.1
Created port 1
+ set port index 0 numrxqs 1 qsize 2048
+ set port index 1 numrxqs 1 qsize 2048
+ set port index 0 rxqmap 0 cpu 7
+ set port index 1 rxqmap 0 cpu 27
+ show port all
INDEX  DEVICE        RX_QUEUES  RXQ_SIZE  TX_QUEUES  TXQ_SIZE  MAC
1      0000:18:00.1  1          2048      2          2048      b8:3f:d2:fa:53:87
0      0000:18:00.0  1          2048      2          2048      b8:3f:d2:fa:53:86
+ show port rxqs
PORT      RXQ_ID    CPU_ID    ENABLED
0         0         7         1
1         0         27        1
+ add ip addr 172.16.0.2/32 port 0
+ add ip addr 172.16.1.2/32 port 1
+ add ip nexthop 172.16.0.1 mac 30:3e:a7:0b:f2:54 port 0
+ add ip nexthop 172.16.1.1 mac 30:3e:a7:0b:f2:55 port 1
+ add ip route 172.16.0.0/24 via 172.16.0.1
+ add ip route 172.16.1.0/24 via 172.16.1.1
+ add ip route 0.0.0.0/0 via 172.16.1.183
+ show ip addr
PORT        ADDRESS
0           172.16.0.2/32
1           172.16.1.2/32
+ show ip route
DESTINATION           NEXT_HOP
172.16.0.1/32         172.16.0.1
172.16.0.2/32         172.16.0.2
172.16.0.0/24         172.16.0.1
172.16.1.1/32         172.16.1.1
172.16.1.2/32         172.16.1.2
172.16.1.0/24         172.16.1.1
0.0.0.0/0             172.16.1.183
+ show ip nexthop
IP              MAC                   PORT    AGE    STATE
172.16.1.183    ??:??:??:??:??:??     ?       ?      gateway
172.16.1.2      30:3e:a7:0b:ea:79     1       0      reachable static local link
172.16.0.2      30:3e:a7:0b:ea:78     0       0      reachable static local link
172.16.0.1      30:3e:a7:0b:f2:54     0       0      reachable static gateway
172.16.1.1      30:3e:a7:0b:f2:55     1       0      reachable static gateway
```

The CLI can be used as a one-shot command (with bash completion built-in):

```console
[root@dio brouter]$ complete -o default -C './build/br-cli -c' ./build/br-cli
[root@dio brouter]$ ./build/br-cli <TAB><TAB>
add                   (Create objects in the configuration.)
clear                 (Clear counters or temporary entries.)
del                   (Delete objects from the configuration.)
-e                    (Abort on first error.)
--err-exit            (Abort on first error.)
--help                (Show usage help and exit.)
-h                    (Show usage help and exit.)
quit                  (Exit the CLI.)
set                   (Modify existing objects in the configuration.)
show                  (Display information about the configuration.)
--socket              (Path to the control plane API socket.)
-s                    (Path to the control plane API socket.)
--trace-commands      (Print executed commands.)
-x                    (Print executed commands.)
[root@dio brouter]$ ./build/br-cli show <TAB><TAB>
graph      (Show packet processing graph info.)
ip         (Show IPv4 stack details.)
port       (Display port details.)
stats      (Print statistics.)
[root@dio brouter]$ ./build/br-cli show graph <TAB><TAB>
dot        (Dump the graph in DOT format.)
stats      (Print graph nodes statistics.)
[root@dio brouter]$ ./build/br-cli show graph stats
NODE               CALLS      PACKETS   PKTS/CALL   CYCLES/CALL    CYCLES/PKT
port_tx           223946     24121370       107.7        6076.0          56.4
ip_input          223946     24121370       107.7        4999.5          46.4
port_rx           268128     24121370        90.0        3648.6          40.6
eth_classify      223946     24121370       107.7        2404.0          22.3
ip_output         223946     24121370       107.7        1518.5          14.1
ip_forward        223946     24121370       107.7        1141.3          10.6
```

## Packet graph

```console
[root@dio brouter]$ ./build/br-cli show graph dot | dot -Tsvg > docs/graph.svg
```

![docs/graph.svg](https://raw.githubusercontent.com/rjarry/brouter/main/docs/graph.svg)

## License

BSD 3 clause.
