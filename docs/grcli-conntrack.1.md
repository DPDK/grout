GRCLI-CONNTRACK 1 @DATE@ "grout @VERSION@"
==========================================

# NAME

**grcli-conntrack** -- grout connection tracking commands

# DESCRIPTION

The **conntrack** commands manage connection tracking in grout,
including viewing active connections, configuring timeouts, and
managing connection state.

These commands send **GR_CONNTRACK_LIST**, **GR_CONNTRACK_FLUSH**,
**GR_CONNTRACK_CONF_GET**, or **GR_CONNTRACK_CONF_SET** API requests. The
server maintains a hash table of tracked connections with RCU-protected
access from datapath workers. Connection state tracking follows TCP state
machine for TCP connections. Idle connections are aged out by a periodic
timer (1 second interval) based on their state and configured timeouts.

**Special cases:**

- **RCU-protected access**: The connection hash table uses atomic operations
  and RCU synchronization to allow lock-free lookups from datapath workers
  while safely modifying the table from the control plane.
- **Changing max_count**: When maximum connections is changed, all existing
  connections are migrated to a new hash table. The old table is freed only
  after RCU grace period ensures no workers are accessing it.
- **ICMP tracking**: Only ICMP echo request/reply packets are tracked using
  the ICMP identifier as the port equivalent. Other ICMP types are not
  tracked yet.
- **Flush operation**: Iterates through the entire hash table and destroys
  all forward-flow entries. Reverse flows are automatically cleaned up.
- **Ageing timer**: Runs every second, checking all connections against their
  state-specific timeout. Uses `last_update` timestamp for idle detection.
- **Zero timeouts ignored**: In config set, timeout values of 0 are ignored
  and keep their previous value. Use non-zero values to change timeouts.

# SYNOPSIS

**grcli** **conntrack** [**show**]

**grcli** **conntrack** **flush**

**grcli** **conntrack** **config** [**show**]

**grcli** **conntrack** **config** **set** [**max** _MAX_]
[**closed-timeout** _CLOSED_] [**new-timeout** _NEW_]
[**established-udp-timeout** _EST_UDP_] [**established-tcp-timeout** _EST_TCP_]
[**half-close-timeout** _HALF_CLOSE_] [**time-wait-timeout** _TIME_WAIT_]

# ARGUMENTS

_MAX_
    Maximum number of connections to track (default: 16384). When changed,
    the server creates a new hash table and mempool, migrates all existing
    connections using RCU synchronization, then frees the old structures.
    This operation is safe but temporarily increases memory usage.

_CLOSED_
    Timeout for closed connections in seconds (default: 5). Applied to
    connections in CONN_S_CLOSED state. Connections idle longer than this
    are destroyed by the ageing timer.

_NEW_
    Timeout for new connections in seconds (default: 5). Applied to
    unsynchronized states (CONN_S_NEW, CONN_S_SIMSYN_SENT,
    CONN_S_SYN_RECEIVED). UDP connections always use this timeout.

_EST_UDP_
    Timeout for established UDP connections in seconds (default: 30). UDP
    is stateless, so "established" means bidirectional traffic seen.

_EST_TCP_
    Timeout for established TCP connections in seconds (default: 300).
    Applied to CONN_S_ESTABLISHED state for TCP connections.

_HALF_CLOSE_
    Timeout for half-closed connections in seconds (default: 120). Applied
    to states CONN_S_FIN_SENT, CONN_S_FIN_RECEIVED, CONN_S_CLOSE_WAIT,
    CONN_S_FIN_WAIT, CONN_S_CLOSING, CONN_S_LAST_ACK.

_TIME_WAIT_
    Timeout for TIME_WAIT state connections in seconds (default: 30).
    Applied to CONN_S_TIME_WAIT state after TCP connection closure.

# EXAMPLES

Display active connections:

```
conntrack show
```

Flush all connection entries:

```
conntrack flush
```

Display connection tracking configuration:

```
conntrack config show
```

Configure connection tracking parameters:

```
conntrack config set max 1024 closed-timeout 2
conntrack config set max 2048 established-tcp-timeout 3600
conntrack config set new-timeout 60 established-udp-timeout 1800
```

Example output:

```
grout# conntrack show
IFACE          ID  STATE        FLOW  SRC         DST         PROTO  SPORT  DPORT  LAST_UPDATE
p0     0x5caefe40  closed       fwd   10.99.0.99  172.16.0.2  TCP    55828   1234            0
                                rev   172.16.0.2  172.16.0.1          1234  21373
p0     0x5caeff00  established  fwd   10.99.0.99  172.16.0.2  UDP    37778   1234            0
                                rev   172.16.0.2  172.16.0.1          1234  28265

grout# conntrack config show
used 2 (0.2%)
max 1024
closed-timeout 2
new-timeout 5
established-udp-timeout 30
established-tcp-timeout 300
half-close-timeout 120
time-wait-timeout 30
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
