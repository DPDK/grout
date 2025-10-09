GRCLI-AFFINITY 1 @DATE@ "grout @VERSION@"
=========================================

# NAME

**grcli-affinity** -- grout CPU affinity and queue mapping commands

# DESCRIPTION

The **affinity** commands manage CPU affinity settings for grout's
control and datapath threads, as well as queue-to-CPU mappings for
optimal performance.

These commands send **GR_INFRA_CPU_AFFINITY_SET**,
**GR_INFRA_CPU_AFFINITY_GET**, **GR_INFRA_RXQ_SET**, or
**GR_INFRA_RXQ_LIST** API requests. When setting CPU affinity, the server
uses `pthread_setaffinity_np()` to pin the control thread and dynamically
creates or destroys datapath worker threads based on the CPU mask. RX queues
are automatically redistributed across available workers. When setting queue
mappings, the CPU must be in the current datapath affinity mask.

**Special cases:**

- **Dynamic worker management**: When datapath CPU affinity changes, workers
  on CPUs removed from the mask are destroyed, and new workers are created
  for CPUs added to the mask. All RX/TX queues are cleared and redistributed.
- **CPU validation**: Manually setting a queue to a CPU outside the datapath
  affinity mask fails with **EINVAL**. The CPU must first be added to the
  datapath mask before queue mapping.
- **Automatic redistribution**: When datapath affinity changes, all existing
  port queues are automatically reassigned to the new worker set in
  round-robin fashion, considering NUMA locality.
- **Control thread affinity**: Setting control CPU affinity also updates the
  control output thread affinity to ensure proper isolation.

# SYNOPSIS

**grcli** **affinity** **cpus** **set** **control** _CPUS_ **datapath** _CPUS_

**grcli** **affinity** **cpus** **show**

**grcli** **affinity** **qmap** **show**

**grcli** **affinity** **qmap** **set** _IFACE_ **rxq** _RXQ_ **cpu** _CPU_

# ARGUMENTS

_CPUS_
    Comma-separated list of CPU cores (e.g., 0,1,2,3 or 1-4). Parsed into
    a `cpu_set_t` bitmask. When setting datapath CPUs, workers are
    dynamically created for new CPUs and destroyed for removed CPUs. All RX
    queues are automatically redistributed across the new worker set. Empty
    CPU sets are ignored (CPU_COUNT == 0).

_IFACE_
    Interface name to configure queue mapping for. Must be a port interface
    (GR_IFACE_TYPE_PORT). The server resolves this to an interface ID and
    then to a port ID before assigning the queue.

_RXQ_
    Receive queue number (0-based). Must be less than the number of RX
    queues configured for the interface. The queue must exist before it can
    be mapped to a CPU.

_CPU_
    CPU core number to map the queue to. **Must be in the current datapath
    affinity mask** or the operation will fail with **EINVAL**. The server
    calls `worker_rxq_assign()` to move the queue to the specified worker.

# EXAMPLES

Set CPU affinity for control and datapath threads:

```
affinity cpus set control 0 datapath 1
affinity cpus set datapath 1,2,3
```

Display current CPU affinity settings:

```
affinity cpus show
```

Display queue-to-CPU mappings:

```
affinity qmap show
```

Configure queue mapping for an interface:

```
affinity qmap set p0 rxq 0 cpu 1
affinity qmap set p0 rxq 1 cpu 2
```

Example output:

```
grout# affinity cpus show
control-cpus 0
datapath-cpus 1,2,3

grout# affinity qmap show
CPU_ID  IFACE  RXQ_ID  ENABLED
1       p0     0       1
2       p0     1       1
3       p1     0       1
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
