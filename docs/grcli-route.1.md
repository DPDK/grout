GRCLI-ROUTE 1 @DATE@ "grout @VERSION@"
======================================

# NAME

**grcli-route** -- grout routing table management commands

# DESCRIPTION

The **route** commands manage IPv4 and IPv6 routing tables in grout,
including adding, deleting, displaying, and looking up routes.

These commands send **GR_IP4_ROUTE_ADD**, **GR_IP4_ROUTE_DEL**,
**GR_IP4_ROUTE_GET**, **GR_IP4_ROUTE_LIST**, **GR_IP6_ROUTE_ADD**,
**GR_IP6_ROUTE_DEL**, **GR_IP6_ROUTE_GET**, or **GR_IP6_ROUTE_LIST** API
requests. The address family (IPv4 or IPv6) is automatically detected from the
address format. The server maintains per-VRF routing tables (RIB - Routing
Information Base) using DPDK rte_rib and rte_rib6 structures. Each route
associates a destination prefix with a nexthop and an origin (user, connected,
or internal).

When adding a route, the server looks up or creates the specified nexthop,
increments its reference count, inserts the route into the RIB, and triggers
route add events. The exist_ok flag allows replacing existing routes without
error. When deleting a route, the nexthop reference count is decremented and
the route is removed from the RIB. Route lookups perform longest prefix
matching to find the best nexthop for a destination address.

**Note:**

- **Per-VRF routing tables**: Each VRF has its own independent routing table
  (rib4/rib6). Routes are isolated between VRFs, allowing overlapping address
  spaces.
- **Route origins**: Routes are tagged with origin (user, connected, internal)
  to distinguish user-configured static routes from automatically created
  connected routes and system-internal routes (e.g., for DNAT).
- **Nexthop reference counting**: Routes hold references to nexthops,
  preventing nexthop deletion while routes exist. This ensures routing table
  consistency.
- **Longest prefix match**: Route lookups use longest prefix matching,
  returning the most specific route for a destination. The RIB structures
  provide O(log n) lookup performance.
- **Automatic nexthop creation**: When adding a route with a gateway address,
  if no nexthop exists for that gateway, the server automatically creates one
  in NEW state, triggering ARP/NDP resolution.

**Special cases:**

- **VRF creation on demand**: Adding a route to a non-existent VRF
  automatically creates the VRF routing table (rib4/rib6).
- **Route replacement**: Adding a route to an existing destination prefix
  replaces the old route. The old nexthop is dereferenced and the new one is
  referenced. Route events are triggered for both deletion and addition.
- **IPv6 link-local scoping**: IPv6 link-local addresses (fe80::/10) are
  scoped to interfaces using the interface ID embedded in the upper 16 bits of
  the address internally.
- **Nexthop lookup for gateway routes**: When adding a route via a gateway IP,
  the server performs a nexthop lookup. If the gateway is not reachable
  (ENETUNREACH), the route add operation fails.
- **Nexthop ID vs gateway address**: Routes can specify either a nexthop ID
  (for pre-created nexthops) or a gateway IP address (for automatic nexthop
  lookup/creation). Only one can be specified per route.

# SYNOPSIS

**grcli** **route** **add** _DEST_ **via** (_NH_|**id** _ID_) [**vrf** _VRF_]

**grcli** **route** **del** _DEST_ [**vrf** _VRF_]

**grcli** **route** **get** _DEST_ [**vrf** _VRF_]

**grcli** **route** [**show**] [**vrf** _VRF_]

# ARGUMENTS

_DEST_
    Destination IP prefix with prefix length (e.g., 16.0.0.0/16,
    fd00:f00:1::/64). For **add** and **del**, this is the route prefix. For
    **get**, this is the destination IP address to look up (longest prefix
    match). The address format determines whether IPv4 or IPv6 API requests
    are used.

_NH_
    Next hop gateway IP address (e.g., 172.16.0.2, fd00:ba4:1::2). The server
    performs a nexthop lookup for this address. If no nexthop exists, one is
    automatically created in NEW state. The nexthop must be reachable
    (directly connected or via another route) or the operation fails with
    **ENETUNREACH**.

_ID_
    Next hop user ID (1 to 4294967294). References a pre-created nexthop by
    its ID. The nexthop must exist or the operation fails with **ENOENT**.
    Use **grcli-nexthop**(1) to create nexthops with specific IDs.

_VRF_
    VRF ID for the route (0 to 65534, default: 0). Routes are added to and
    looked up in the specified VRF routing table. In **show**, use
    GR_VRF_ID_ALL to display routes from all VRFs.

# EXAMPLES

Add IPv4 routes with gateway addresses:

```
route add 16.0.0.0/16 via 172.16.0.2
route add 0.0.0.0/0 via 10.0.0.1
```

Add IPv6 routes with gateway addresses:

```
route add fd00:f00:1::/64 via fd00:ba4:1::2
route add ::/0 via 2345::1
```

Add routes using pre-created nexthop IDs:

```
route add 16.1.0.0/16 via id 45
route add fd00:f00:2::/64 via id 45
```

Add routes to specific VRFs:

```
route add 16.0.0.0/16 via 172.16.0.2 vrf 1
route add 16.1.0.0/16 via 172.16.0.2 vrf 2
```

Delete routes:

```
route del 16.0.0.0/16
route del fd00:f00:1::/64 vrf 1
```

Look up the best route for a destination address:

```
route get 16.0.5.1
route get fd00:f00:1::5
```

Display all routes or routes in a specific VRF:

```
route show
route show vrf 1
```

Example output:

```
grout# route show
VRF  DESTINATION    NEXT_HOP
0    16.0.0.0/16    type=L3 id=1 iface=p0 vrf=0 origin=user af=IPv4 addr=172.16.0.2
0    16.1.0.0/16    type=L3 id=45 iface=p1 vrf=0 origin=user af=unspec static link
0    172.16.0.0/24  type=L3 iface=p0 vrf=0 origin=INTERNAL af=IPv4 addr=172.16.0.1/24
```

# SEE ALSO

**grcli**(1), **grcli-nexthop**(1), **grcli-address**(1), **grcli-interface**(1)

# AUTHORS

Created and maintained by Robin Jarry.
