GRCLI-STATS 1 @DATE@ "grout @VERSION@"
======================================

# NAME

**grcli-stats** -- grout packet processing statistics commands

# DESCRIPTION

The **stats** commands display packet processing statistics from grout's
datapath workers, including per-node packet counts, batch processing metrics,
and CPU cycle measurements for performance analysis.

These commands send **GR_INFRA_STATS_GET** or **GR_INFRA_STATS_RESET** API
requests. The server collects statistics from all worker threads, aggregating
per-node counters for packets, batches, and CPU cycles. Software stats show
graph node processing metrics calculated from worker statistics structures.
Hardware stats show NIC-level extended statistics retrieved via DPDK
rte_eth_xstats_get for physical interface counters.

When displaying software stats, the server calculates derived metrics including
packets per batch (throughput efficiency), cycles per batch (processing cost),
and cycles per packet (per-packet overhead). An "idle" pseudo-node tracks
worker sleep time when no packets are available. An "overhead" pseudo-node
measures graph framework overhead excluding actual node processing.

**Note:**

- **Software vs hardware stats**: Software stats track packet processing
  through graph nodes in the datapath worker threads, measuring batches,
  packets, and CPU cycles. Hardware stats show NIC-level counters like
  interface RX/TX packets, errors, and drops from the physical hardware.
- **Statistics aggregation**: Stats are aggregated across all worker threads
  unless a specific CPU ID is provided. Each worker maintains its own
  statistics structure atomically updated during packet processing.
- **Pseudo-nodes**: The "idle" node shows time workers spent sleeping when no
  packets were available (based on n_sleeps and sleep_cycles). The "overhead"
  node shows graph framework overhead calculated as loop_cycles minus node
  processing cycles.
- **Ordering options**: Results can be sorted by name (alphabetical), packets
  (decreasing packet count), cycles (decreasing cycle count, default for
  software), or graph (topological order following packet flow through nodes).
- **Pattern filtering**: Use glob patterns to filter stats by name (e.g., "ip*"
  shows all IP-related nodes, "port*" shows port nodes). Patterns use standard
  shell wildcards.

**Special cases:**

- **Zero value filtering**: By default, stats with zero packets are hidden to
  reduce noise. The "idle" and "overhead" pseudo-nodes are shown if they have
  non-zero batches. Use **zero** flag to show all stats including zeros.
- **Per-CPU stats**: Specify a CPU ID to show stats from only that worker
  thread. Useful for debugging CPU-specific performance issues or validating
  queue-to-CPU mappings. CPU ID must match a datapath worker CPU.
- **Brief mode**: Shows only node names and packet counts in simple two-column
  format without batch and cycle metrics. Useful for quick packet flow
  verification without performance details.
- **Stats reset**: Resets all worker statistics counters to zero. This affects
  all CPUs simultaneously and cannot be undone. Use before starting performance
  measurements to get clean baselines.
- **Hardware stats availability**: Hardware stats are only available for port
  interfaces. Virtual interfaces (loopback, VLAN, IPIP) do not provide hardware
  counters. The available counters depend on the NIC driver capabilities.

# SYNOPSIS

**grcli** **stats** [**show**] [**software**|**hardware**] [**brief**] [**zero**]
[**pattern** _PATTERN_] [**cpu** _CPU_] [**order** _ORDER_]

**grcli** **stats** **reset**

# ARGUMENTS

**software**
    Display software statistics from graph node processing (default). Shows
    packet counts, batches, and CPU cycles for each node in the packet
    processing graph. Includes calculated metrics for efficiency analysis.

**hardware**
    Display hardware statistics from NIC extended stats. Shows interface-level
    counters like RX/TX packets, bytes, errors, and drops from the physical
    hardware. Only available for port interfaces.

**brief**
    Show only node names and packet counts in simple format. Omits batch and
    cycle metrics, cycles per packet, and other derived calculations. Useful
    for quick verification without performance details.

**zero**
    Include statistics with zero packets in the output. By default, nodes with
    no packets processed are hidden to reduce noise. This flag shows all nodes
    regardless of activity.

**pattern** _PATTERN_
    Filter statistics by glob pattern (e.g., "ip*", "port*", "*output*"). Uses
    standard shell wildcard matching (* matches any characters, ? matches
    single character). Only stats matching the pattern are displayed.

**cpu** _CPU_
    Show statistics from a specific CPU worker thread (0 to 65534). By
    default, stats are aggregated across all workers. The CPU ID must
    correspond to a datapath worker CPU from the affinity configuration.

**order** _ORDER_
    Sort order for results. Options: **name** (alphabetical), **packets**
    (decreasing packet count), **cycles** (decreasing CPU cycles, default for
    software stats), **graph** (topological order following packet flow). For
    hardware and brief mode, **name** is the default.

# EXAMPLES

Display software statistics (default, sorted by cycles):

```
stats show
stats show software
```

Display software statistics sorted by packet count:

```
stats show order packets
```

Display only IP-related node statistics:

```
stats show pattern "ip*"
```

Display statistics from a specific CPU:

```
stats show cpu 1
```

Display hardware statistics from NICs:

```
stats show hardware
```

Display brief packet counts only:

```
stats show brief
```

Reset all statistics counters:

```
stats reset
```

Example software stats output (with traffic):

```
grout# stats show software
NODE         BATCHES  PACKETS  PKTS/BATCH  CYCLES/BATCH  CYCLES/PKT
port_rx       757792 22623757        29.9        1776.4        59.5
ip_input      333675 22623757        67.8        3091.0        45.6
port_tx       333675 22623757        67.8        1984.2        29.3
eth_input     757792 22623757        29.9         659.7        22.1
eth_output    333675 22623757        67.8        1323.4        19.5
ip_output     333675 22623757        67.8         926.3        13.7
ip_forward    333675 22623757        67.8         691.8        10.2
```

Example with no traffic:

```
grout# stats show software
NODE      BATCHES  PACKETS  PKTS/BATCH  CYCLES/BATCH  CYCLES/PKT
idle         2362        0         0.0      969589.4         0.0
overhead  3195392        0         0.0         121.5         0.0
```

Example hardware stats output:

```
grout# stats show hardware
p0:rx_good_packets 1234567
p0:tx_good_packets 1234560
p0:rx_good_bytes 123456789
p0:tx_good_bytes 123456000
```

# SEE ALSO

**grcli**(1), **grcli-affinity**(1), **grcli-graph**(1)

# AUTHORS

Created and maintained by Robin Jarry.
