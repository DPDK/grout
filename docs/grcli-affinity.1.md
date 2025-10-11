GRCLI-AFFINITY 1 @DATE@ "grout @VERSION@"
=========================================

# NAME

**grcli-affinity** -- grout CPU affinity and queue mapping commands

# DESCRIPTION

The **affinity** commands manage CPU affinity settings for grout's
control and datapath threads, as well as queue-to-CPU mappings for
optimal performance.

# SYNOPSIS

**grcli** **affinity** **cpus** **set** **control** _CPUS_ **datapath** _CPUS_

**grcli** **affinity** **cpus** **show**

**grcli** **affinity** **qmap** **show**

**grcli** **affinity** **qmap** **set** _IFACE_ **rxq** _RXQ_ **cpu** _CPU_

# ARGUMENTS

_CPUS_
    Comma-separated list of CPU cores (e.g., 0,1,2,3).

_IFACE_
    Interface name to configure queue mapping for.

_RXQ_
    Receive queue number (0-based).

_CPU_
    CPU core number to map the queue to.

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
