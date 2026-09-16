# Grout Architecture

`grout` is a DPDK-based software router that uses the `rte_graph` library for
datapath packet processing. It implements an L3 forwarding stack in userspace.
It is configured over a UNIX socket API and a CLI (`grcli`), and integrates with
FRR for dynamic routing via a dedicated zebra dplane plugin.

This document describes the high-level architecture.

## Build and test

grout uses `meson` with a `GNUmakefile` wrapper. DPDK is built as a meson
subproject and statically linked. This provides exact version control and
simplifies carrying local patches. On distributions that package DPDK (Fedora,
EPEL), the system-installed version can be used instead. Dynamic linking of
DPDK libraries comes with a 15% performance penalty.

The project requires C23 (`gcc` 13+ or `clang` 15+) for typed enums (`enum
: uint16_t`) and variadic macro features.

### Unit tests

Unit tests use `cmocka`, which supports mocking C symbols -- necessary for
testing static functions. Tests are embedded alongside source code, guarded by
`__GROUT_UNIT_TEST__`, keeping them close to the code they test.

### Integration tests

Shell scripts in `smoke/` create network namespaces with veth pairs connected to
grout via DPDK tap/vhost devices. Each test is self-contained and can be run
individually (`sudo smoke/foo_test.sh build`) for debugging. Plain shell scripts
were preferred over a dedicated integration test framework for their simplicity
and debuggability.

## Module system

Modules register via `module_register()` with a `depends_on` string
(comma-separated, supports `fnmatch` patterns). They are topologically sorted at
startup; circular or missing dependencies cause `ABORT`. Each module has
`init`/`fini` callbacks called in dependency/reverse order.

This is simpler than VPP's plugin system (dynamic `.so` loading via `dlopen`
with constructor-based registration) but sufficient for grout's scope. Modules
are statically linked, favoring build-time safety and simpler deployment over
runtime flexibility.

The interface type system uses a vtable pattern (`struct iface_type` with
function pointers for `init`, `fini`, `reconfig`, get/set MAC, set MTU, set
up/down, etc.), allowing new interface types to be added without modifying core
code. The `BASE()` macro creates anonymous unions (using `-fms-extensions`) for
struct embedding with direct field access and type enforcement.

## Packet processing: `rte_graph`

grout decomposes its forwarding pipeline into a directed acyclic graph of
nodes. Each node is a small function that performs one operation on a batch of
packets and passes them to the next node. The general flow is:

```
port_rx -> iface_input -> eth_input -> ip_input
                                           |
                                           v
                                       ip_forward
                                           |
                                           v
port_tx <- iface_output <- eth_output <- ip_output
```

This graph model is not unique to grout. FreeBSD's netgraph framework (since
1998) provides a similar kernel-space graph for packet processing, used by
Juniper in JunOS. VPP (Vector Packet Processing) has its own custom graph engine
predating `rte_graph`.

grout uses DPDK's `rte_graph` library. The primary motivation was dogfooding:
grout was originally a test vehicle for DPDK, and using DPDK's own graph library
exercises it in ways that no other application does. `rte_graph` provides
feature arcs and other extensibility mechanisms, but grout does not use them --
the graph topology is determined at configuration time and rebuilt when it
changes. This keeps the datapath simple and predictable.

### Strict OSI layer separation

Each graph node operates at exactly one OSI layer. `eth_input` pops the Ethernet
header and dispatches by ethertype. `ip_input` validates the IP header and
performs a FIB lookup. `ip_forward` decrements TTL and updates the checksum.
`eth_output` reconstructs the Ethernet header. No node teleports packets between
layers.

This separation is what makes grout extensible. Adding L2 bridging, VXLAN, SRv6,
or NAT required adding new nodes and edges to the graph without modifying
existing ones. The architecture remained stable through every major feature
addition.

### Extensible dispatch via edge tables

Several nodes use statically-sized arrays for O(1) protocol dispatch.
`eth_input` has a 64K-entry table indexed by ethertype. `ip_input` dispatches
by nexthop type. `l4_input_local` dispatches by UDP port number. `iface_input`
dispatches by interface mode (VRF, bridge, bond, cross-connect). New protocols
register edges at initialization time.

### One node per port queue

Each port/queue pair gets its own node clone (e.g. `port_rx-p0q0`,
`port_rx-p0q1`, `port_tx-p2q0`). A worker's graph includes only the RX clones
for its assigned queues but all TX clones, with a `port_output` node steering
packets to the correct TX clone. This design enables NUMA-aware queue
distribution and eliminates any per-packet queue selection logic in the hot
path.

## Threading model

grout splits CPU cores at startup. The first available core runs the main
thread (control plane). All remaining cores run datapath worker threads.

### Workers

Each worker is a pthread pinned to a single CPU core, running
`rte_graph_walk()` in a tight loop. Workers have no locks in the hot path. They
check for configuration changes every 256 graph walks via an atomic load
(empirically tuned). When idle, workers incrementally sleep up to
a configurable maximum, resetting on any packet activity.

Configuration changes trigger a two-phase graph swap. The control plane builds
new graphs in the background, then signals workers via an atomic flag. Each
worker has two graph slots (`graph[0]`/`graph[1]`) for lock-free swapping: stop
looping by reading the atomic, pick up the new graph pointer, continue. The
pause is effectively instant -- no barrier synchronization, no locking.

This differs from VPP, which uses a full barrier mechanism (stop all workers,
make the change, release). VPP's approach is simpler to reason about but causes
a brief datapath stall. grout's approach is driven by `rte_graph`'s API: graphs
cannot be modified in place, they must be rebuilt.

### Control plane

The main thread runs a `libevent` event loop handling the API socket, ARP/NDP
aging, link status monitoring, timers, and inter-module events. `libevent` was
chosen for availability (works on old RHEL), maturity, and its `bufferevent`
abstraction for socket I/O.

Events from the datapath (ARP replies, MAC learning) flow through a control
queue: a DPDK ring with a semaphore-triggered `libevent` user event. This keeps
the control plane single-threaded while accepting asynchronous notifications
from any worker. A dispatch graph model (some nodes handled by different CPUs)
would be preferable, but `rte_graph`'s pipeline mode is not yet mature enough to
rely on for this.

### Metrics

A separate thread runs an OpenMetrics (Prometheus-compatible) HTTP endpoint
with read-only access to datapath structures. Interface statistics use
per-lcore counters to avoid contention; the metrics thread aggregates them.

## Memory and concurrency

grout uses DPDK's native `rte_mbuf` for packet buffers, allocated from
hugepage-backed mempools. Unlike VPP, which has a custom buffer layer with
32-bit index compression (halving the memory footprint of packet vectors at the
cost of implementation complexity), grout uses `rte_mbuf` pointers directly.
This avoids a custom abstraction layer at the cost of wider pointers.

All shared data structures (FIBs, nexthop tables, FDB, interfaces) use DPDK's
QSBR (quiescent state based reclamation) model for lock-free concurrent access.
Workers call `rte_rcu_qsbr_quiescent()` periodically; the control plane calls
`rte_rcu_qsbr_synchronize()` before freeing shared data. DPDK hash tables use
`RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` for lockfree reads. Nexthops use
traditional reference counting alongside RCU.

The FIB stores raw nexthop pointers as values (using 63 of the 64 bits
available in `rte_fib`). This eliminates any ID-to-pointer indirection in the
forwarding hot path: `fib4_lookup()` returns a nexthop pointer directly.

## API and configuration

grout is configured over a UNIX socket using a binary message protocol. Each
request carries a 32-bit type (`module_id << 16 | request_id`), and handlers are
dispatched from a two-level array indexed by module and request -- `O(1)` lookup
with natural module isolation.

The API uses raw C structs as payloads. This was a deliberate choice:
simplicity, zero overhead, no boilerplate, no code generation. Protobuf and
Cap'n Proto were both tried in the project's early days but dropped -- their C
support was too limited for the benefit. With only two clients (grcli and the
FRR plugin), a serialization framework would have been over-engineering.

List operations use a streaming protocol: handlers send multiple responses
terminated by an empty payload. The client iterates with
`gr_api_client_stream_foreach()`, which supports `break` with automatic drain.

### grcli

`grcli` is a separate binary that connects to the daemon over the UNIX socket.
It uses `libecoli` for parsing, with hierarchical command contexts
(`CLI_COMMAND`/`CLI_CONTEXT` macros) providing tab completion and structured
command trees.

`grcli` is not a Cisco IOS or JunOS CLI. It is a low-level operational and
debugging tool for power users and sysadmins, analogous to iproute2 or sysctl.
It is not intended for network operators managing production infrastructure
through a terminal. Production deployments are expected to use the API directly
(automation, orchestration) or higher-level interfaces such as `vtysh`,
NETCONF/YANG, or RESTCONF.

grout's design separates the CLI process from the datapath. This provides crash
isolation (a misbehaving CLI command cannot take down the forwarding plane) and
fits naturally into service management (a `systemd` service has no stdin --
configuration must come from the API socket).

### Events

Two parallel event systems serve different purposes. Internal C callbacks
(registered via `event_subscribe()`) are invoked synchronously for inter-module
communication -- for example, the interface module subscribes to its own
events to propagate status changes to sub-interfaces. External API client
subscriptions are asynchronous: events are serialized and written to the
client's socket. The split avoids serialization overhead for internal
subscribers.

## Routing and FIB

IPv4 routes use DPDK's `rte_fib` library with the `DIR24_8` algorithm. IPv6
uses `rte_fib6`, which is functional but incomplete (upstream improvements are
ongoing). Both use RCU with deferred queue mode for safe concurrent access.
Switching from synchronous RCU to deferred queues improved IPv6 route insertion
from 1.3K routes/s to 77K routes/s -- the synchronous mode blocked the control
plane on every tbl8 group free until all workers passed through a quiescent
state.

Each VRF maintains its own FIB and nexthop table. VRFs use names rather than
numeric IDs to match the Linux `l3mdev` model where VRF devices need names for
FRR integration.

The nexthop system is the central forwarding abstraction. L3 nexthops have
a state machine (NEW -> PENDING -> REACHABLE -> STALE -> FAILED) that
drives ARP/NDP resolution. Nexthop types include standard L3 with MAC
resolution, SRv6, DNAT, blackhole, reject, and ECMP groups. Origins (link,
user, DHCP, BGP, OSPF) are compatible with Linux RTPROT values for FRR
integration.

## FRR integration: why not netlink

Most DPDK routers mirror the Linux kernel FIB into userspace. FRR programs
routes into the kernel via netlink. A synchronization agent listens to netlink
broadcasts and translates them into the DPDK application's parlance. This
architecture has three drawbacks:

1. **Two FIBs, two sources of truth.** Netlink notifications are
   fire-and-forget. If the sync agent fails to program a route, the kernel FIB
   and the DPDK FIB silently diverge. There is no error reporting path.

2. **Netlink is slow.** The kernel takes exclusive locks during route
   operations. Notifications require kernel-userspace roundtrips. Under heavy
   route churn (BGP convergence), this becomes a bottleneck.

3. **Hard coupling to Linux.** The entire synchronization model depends on the
   kernel networking stack being present and active. This makes containerized
   deployment harder and adds an unnecessary dependency.

grout takes a different approach. FRR has a dataplane plugin API (dplane) that
was originally designed for hardware offload. grout provides a zebra dplane
plugin that intercepts route installs before they hit the kernel and programs
them directly into the DPDK FIB. The result is a single FIB, a single source of
truth, with error reporting.

This was not the easier path. The only viable routing control plane on Linux is
FRR, so the tight coupling is an acceptable trade-off for bypassing the kernel
roundtrip.

### Control plane traffic termination

When grout owns the NIC via DPDK, FRR daemons (bgpd, isisd) need to send and
receive packets but have no Linux interface to bind to. grout solves this with
control plane representors:

- **`gr-loop`**: A TUN device with a default route. FRR daemons use standard
  TCP/UDP sockets (connect, bind) through this device. The kernel handles TCP;
  grout only forwards packets.

- **Per-port TAPs (p0, p1, ...)**: Each DPDK port gets a TAP device with ARP
  disabled and a /32 address mirroring the DPDK port's IP address. This
  prevents Linux from doing anything clever -- it only knows addresses, not
  routes or VLANs. IS-IS and other protocols that need raw sockets bind to
  these TAPs.

Non-default VRFs create a Linux `l3mdev` device with the representors enslaved
to it, so FRR daemons see proper VRFs and bind sockets per VRF.

The kernel is used solely for local traffic termination, never for forwarding.
Linux does not synchronize routes, VLAN numbers, or any forwarding state. It
only knows addresses.
