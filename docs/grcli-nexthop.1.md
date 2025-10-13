GRCLI-NEXTHOP 1 @DATE@ "grout @VERSION@"
========================================

# NAME

**grcli-nexthop** -- grout next hop management commands

# DESCRIPTION

The **nexthop** commands manage next hop information in grout's routing
system, including next hop creation, deletion, display, and configuration
management.

These commands send **GR_NH_LIST**, **GR_NH_ADD**, **GR_NH_DEL**,
**GR_INFRA_NH_CONFIG_GET**, or **GR_INFRA_NH_CONFIG_SET** API requests. Next
hops are fundamental routing objects that determine where packets should be
forwarded. The server maintains a hash table of next hops with various states
(new, pending, reachable, stale, failed) and performs neighbor discovery (ARP
for IPv4, NDP for IPv6) to resolve next hop MAC addresses. Next hops can be
explicitly created or automatically managed by the routing system when routes
or addresses are configured.

**Note:**

- **Next hop states**: Next hops transition through states based on neighbor
  discovery probes: NEW (just created), PENDING (probe sent), REACHABLE
  (confirmed via ARP/NDP), STALE (lifetime expired, needs refresh), FAILED
  (all probes sent without reply). The ageing mechanism runs every second to
  update states and send probes.
- **Automatic creation**: When adding routes or IP addresses, the system
  automatically creates associated next hops. For connected routes, local next
  hops are created. For static routes, next hops with the specified gateway are
  created or looked up.
- **Packet holding**: When a next hop is in PENDING or STALE state, outgoing
  packets are queued (up to max_held_pkts, default 256) until the next hop is
  resolved or declared failed. This prevents packet loss during neighbor
  discovery.
- **Internal next hops**: System-generated next hops (for local addresses,
  connected routes, etc.) have origin=INTERNAL and are not shown by default.
  Use the **internal** flag to include them in listings.

**Special cases:**

- **Next hop ID assignment**: When creating next hops, you can optionally
  specify an ID. If omitted, the system assigns the next available ID starting
  from 1. ID 0 is reserved and means "unset".
- **Deleting in-use next hops**: Attempting to delete a next hop that is
  referenced by routes fails with **EBUSY**. Delete the routes first, then the
  next hop.
- **Probe behavior**: STALE next hops are sent unicast probes (default max 3)
  followed by broadcast/multicast probes (default max 3) before being marked as
  FAILED and destroyed after the unreachable timeout.
- **Configuration changes**: Changing max_count requires recreating the next
  hop hash table, which involves copying all existing next hops. This is safe
  but temporarily increases memory usage.

# SYNOPSIS

**grcli** **nexthop** [**show**] [**vrf** _VRF_] [**type** _TYPE_]
[**internal**]

**grcli** **nexthop** **add** **l3** **iface** _IFACE_ [**id** _ID_]
[**address** _IP_] [**mac** _MAC_]

**grcli** **nexthop** **add** **blackhole**|**reject** [**id** _ID_]
[**vrf** _VRF_]

**grcli** **nexthop** **del** _ID_

**grcli** **nexthop** **config** [**show**]

**grcli** **nexthop** **config** **set** [**max** _MAX_]
[**lifetime** _LIFE_] [**unreachable** _UNREACH_] [**held-packets** _HELD_]
[**ucast-probes** _UCAST_] [**bcast-probes** _BCAST_]

# ARGUMENTS

_VRF_
    VRF (Virtual Routing and Forwarding) domain ID (0-65534). Default is to
    show all VRFs. Use **vrf** to filter next hops by routing domain.

_TYPE_
    Next hop type to filter by. Valid types: **L3** (Layer 3 routing with IP
    address and MAC), **blackhole** (silently drop packets), **reject** (drop
    with ICMP unreachable), **dnat** (destination NAT), **snat** (source NAT),
    **encap** (tunnel encapsulation). Default shows all types.

_IFACE_
    Output interface name for the next hop. The server resolves this to an
    interface ID. The interface must exist or the operation fails with
    **ENODEV**.

_ID_
    Next hop ID (1-4294967294). When adding, if omitted, the system assigns the
    next available ID. When deleting, specifies which next hop to remove. ID 0
    is reserved.

_IP_
    IPv4 or IPv6 gateway address for L3 next hops. If omitted when adding an L3
    next hop, creates a link-local next hop (packets forwarded directly on the
    interface using the destination IP for ARP/NDP resolution).

_MAC_
    Ethernet MAC address in colon-separated hexadecimal format (e.g.,
    f0:0d:ac:dc:00:00). If specified when adding an L3 next hop, the next hop
    is marked as static and REACHABLE immediately without performing neighbor
    discovery.

_MAX_
    Maximum number of next hops for all address families (default: 131072).
    Must be a power of 2. Changing this recreates the next hop hash table.

_LIFE_
    Reachable next hop lifetime in seconds (default: 1200). After this time
    without confirmation, the next hop transitions to STALE and probes are
    sent.

_UNREACH_
    Unreachable next hop lifetime in seconds (default: 60). After probes fail
    and this time expires, the next hop is destroyed and packets are dropped.

_HELD_
    Maximum number of packets to queue per next hop while waiting for neighbor
    discovery resolution (default: 256). Additional packets are dropped.

_UCAST_
    Maximum number of unicast ARP/NDP probes to send when lifetime expires
    (default: 3). Sent to the next hop's last known MAC address.

_BCAST_
    Maximum number of broadcast (ARP) or multicast (NDP) probes to send after
    unicast probes fail (default: 3). Broadcast to all hosts on the segment.

**internal**
    Include internal next hops in the listing. Internal next hops are
    system-generated for local addresses, connected routes, and other automatic
    configurations. They have origin=INTERNAL.

**blackhole**
    Create a next hop that silently discards all packets. Used for routing
    traffic into a "black hole" without generating ICMP errors.

**reject**
    Create a next hop that drops packets and sends ICMP Destination Unreachable
    messages back to the sender. More informative than blackhole.

# EXAMPLES

Show all next hops (excluding internal):

```
nexthop show
```

Example output:

```
VRF  ID  ORIGIN  IFACE    TYPE  INFO
0    1   user    ha2dcn0  L3    af=IPv4 addr=172.16.0.2 state=reachable mac=ba:d0:ca:ca:00:00
0    45  user    ha2dcn1  L3    af=unspec static link
```

Show next hops including internal system-generated ones:

```
nexthop show internal
```

Show next hops filtered by VRF and type:

```
nexthop show vrf 0 type L3
```

Add a Layer 3 next hop with gateway address:

```
nexthop add l3 iface p0 address 172.16.0.1
nexthop add l3 iface p0 id 100 address 2001:db8::1
```

Add a Layer 3 next hop with static MAC (no neighbor discovery):

```
nexthop add l3 iface p0 address 172.16.0.1 mac f0:0d:ac:dc:00:01
```

Add a link-local next hop (no gateway, use destination IP for resolution):

```
nexthop add l3 iface p0
```

Add blackhole and reject next hops:

```
nexthop add blackhole vrf 0
nexthop add reject id 999 vrf 0
```

Delete a next hop by ID:

```
nexthop del 45
```

Show current next hop configuration:

```
nexthop config show
```

Configure next hop parameters:

```
nexthop config set max 262144 lifetime 1800 unreachable 120
nexthop config set held-packets 512 ucast-probes 5 bcast-probes 5
```

# SEE ALSO

**grcli**(1), **grcli-address**(1), **grcli-interface**(1)

# AUTHORS

Created and maintained by Robin Jarry.
