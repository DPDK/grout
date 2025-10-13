GRCLI-GRAPH 1 @DATE@ "grout @VERSION@"
======================================

# NAME

**grcli-graph** -- grout packet processing graph visualization commands

# DESCRIPTION

The **graph** commands provide visualization of grout's packet processing
graph in DOT format (GraphViz), showing the flow of packets through various
processing nodes and their interconnections. The output can be piped to
GraphViz tools for rendering as images.

The command sends a **GR_INFRA_GRAPH_DUMP** API request to the grout daemon,
which iterates through all registered DPDK rte_graph nodes and generates a
DOT representation of their connections. Source nodes (packet entry points)
are displayed in blue, error/sink nodes in orange.

**Note**: The graph command requires at least one interface to be configured.
An empty graph will be returned if no interfaces exist, as no packet
processing nodes will be instantiated.

# SYNOPSIS

**grcli** **graph** [**show**] [**brief**|**full**]

# ARGUMENTS

**brief**
    Hide error nodes from the graph output (default behavior). The server
    filters out nodes with zero outgoing edges and nodes whose name contains
    "error". This shows only the main packet processing path through the
    system. Sets flags=0 in the API request.

**full**
    Show all nodes including error nodes. Sets the
    **GR_INFRA_GRAPH_DUMP_F_ERRORS** flag in the API request, causing the
    server to include all nodes regardless of type. Provides complete
    visibility into all possible packet paths including error handling and
    drop points.

**show**
    Optional keyword that explicitly requests graph visualization. Can be
    omitted. Has no effect on the API request or output.

# EXAMPLES

Display the packet processing graph excluding error nodes:

```
graph show brief
```

Example output (DOT format):

```
digraph grout {
	rankdir=LR;
	node [margin=0.02 fontsize=11 fontname=sans];
	"control_input" [color=blue style=bold];
	"control_input" -> "loopback_input" [color=blue style=bold];
	"control_input" -> "arp_output_request" [color=blue style=bold];
	"eth_input";
	"eth_input" -> "arp_input";
	"eth_input" -> "ip_input";
	"eth_input" -> "ip6_input";
	"port_rx" [color=blue style=bold];
	"port_rx" -> "eth_input" [color=blue style=bold];
	"port_tx" [color=blue style=bold];
}
```

Display the complete graph including all error nodes:

```
graph show full
```

Display the graph (brief mode is default):

```
graph show
graph
```

Convert the graph to SVG format using GraphViz:

```
graph show brief | dot -Tsvg > graph.svg
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
