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
br#
quit                 Exit the CLI.
route4               Manage IPv4 routes.
nh4                  Manage IPv4 next hops.
stats                Manage stack statistics.
rxq                  Manage ports RX queues.
port                 Manage ports.
graph                Get information about the packet processing graph.
```

Multiple commands can be piped into standard input:

```console
[root@dio brouter]$ ./build/br-cli -ex < commands.list
+ port add 0000:18:00.0
Created port 0
+ port add 0000:18:00.1
Created port 1
+ port set 0 qsize 4096
+ port set 1 qsize 4096
+ rxq set port 0 rxq 0 cpu 7
+ rxq set port 1 rxq 0 cpu 27
+ port list
INDEX  DEVICE        RX_QUEUES  RXQ_SIZE  TX_QUEUES  TXQ_SIZE  MAC
1      0000:18:00.1  1          4096      2          4096      b8:3f:d2:fa:53:87
0      0000:18:00.0  1          4096      2          4096      b8:3f:d2:fa:53:86
+ rxq list
PORT      RXQ_ID    CPU_ID    ENABLED
0         0         7         1
1         0         27        1
+ nh4 add 172.16.0.1 mac b8:3f:d2:fa:53:7a port 0
+ nh4 add 172.16.1.1 mac b8:3f:d2:fa:53:7b port 1
+ route4 add 172.16.0.0/24 via 172.16.0.1
+ route4 add 172.16.1.0/24 via 172.16.1.1
+ route4 add 192.168.0.0/16 via 172.16.0.1
+ route4 add 0.0.0.0/0 via 172.16.1.1
```

The CLI can be used as a one-shot command (with bash completion built-in):

```console
[root@dio brouter]$ complete -C './build/br-cli --bash-complete' ./build/br-cli
[root@dio brouter]$ ./build/br-cli <TAB><TAB>
-e                    (Abort on first error.)
--err-exit            (Abort on first error.)
graph                 (Get information about the packet processing graph.)
--help                (Show usage help and exit.)
-h                    (Show usage help and exit.)
nh4                   (Manage IPv4 next hops.)
port                  (Manage ports.)
quit                  (Exit the CLI.)
route4                (Manage IPv4 routes.)
rxq                   (Manage ports RX queues.)
--socket              (Path to the control plane API socket.)
-s                    (Path to the control plane API socket.)
stats                 (Manage stack statistics.)
--trace-commands      (Print executed commands.)
-x                    (Print executed commands.)
[root@dio brouter]$ ./build/br-cli stats reset
[root@dio brouter]$ ./build/br-cli graph dump
digraph "br-0037" {
        rankdir=LR;
        node [margin=0.02 fontsize=11 fontname=sans];
        "ipv4_rewrite_ttl_exceeded" [color=darkorange];
        "ipv4_rewrite_no_next_hop" [color=darkorange];
        "ipv4_rewrite";
        "ipv4_rewrite" -> "eth_tx";
        "ipv4_rewrite" -> "ipv4_rewrite_no_next_hop";
        "ipv4_rewrite" -> "ipv4_rewrite_ttl_exceeded";
        "ipv4_lookup_bad_length" [color=darkorange];
        "ipv4_lookup_no_route" [color=darkorange];
        "ipv4_lookup_bad_checksum" [color=darkorange];
        "ipv4_lookup";
        "ipv4_lookup" -> "ipv4_rewrite";
        "ipv4_lookup" -> "ipv4_lookup_bad_checksum";
        "ipv4_lookup" -> "ipv4_lookup_no_route";
        "ipv4_lookup" -> "ipv4_lookup_bad_length";
        "eth_tx_error" [color=darkorange];
        "eth_tx";
        "eth_tx" -> "eth_tx_error";
        "eth_rx" [color=blue style=bold];
        "eth_rx" -> "eth_classify" [color=blue style=bold];
        "eth_classify_unknown_ptype" [color=darkorange];
        "eth_classify";
        "eth_classify" -> "eth_classify_unknown_ptype";
        "eth_classify" -> "ipv4_lookup";
}
[root@dio brouter]$ ./build/br-cli graph stats
NODE               CALLS     PACKETS   PKTS/CALL  CYCLES/CALL    CYCLES/PKT
eth_tx            449804   114771409       255.2      79044.8         309.8
ipv4_rewrite      449804   114771409       255.2      14291.0          56.0
ipv4_lookup       449804   114771409       255.2      11872.2          46.5
eth_rx            857824   114771409       133.8       4452.6          33.3
eth_classify      449804   114771409       255.2       1818.2           7.1
```

## License

BSD 3 clause.
