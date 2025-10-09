GRCLI-DNAT44 1 @DATE@ "grout @VERSION@"
=======================================

# NAME

**grcli-dnat44** -- grout destination NAT (DNAT) configuration commands

# DESCRIPTION

The **dnat44** commands configure static destination NAT rules in grout,
allowing incoming traffic to be redirected to different internal IP
addresses.

These commands send **GR_DNAT44_ADD**, **GR_DNAT44_DEL**, or
**GR_DNAT44_LIST** API requests. When adding a rule, the server creates a
DNAT nexthop and inserts a /32 route into the routing table for the match
address. An internal L3 nexthop is also created to respond to ARP requests
for the match address. A reverse SNAT44 static policy is automatically
created to handle return traffic. Deletion removes the route, nexthop, and
associated SNAT policy.

**Note:**

- **No port translation**: DNAT44 operates at IP layer only. Port numbers are
  not translated or matched. Use connection tracking for port-based NAT.
- **Route insertion**: A /32 host route with GR_NH_ORIGIN_INTERNAL is
  automatically inserted into the RIB for the match address, directing
  matching traffic to the DNAT nexthop for translation.
- **Automatic ARP handling**: Grout automatically responds to ARP requests for
  DNAT match addresses as if they were local addresses by creating an internal
  L3 nexthop with GR_NH_F_LOCAL flag.
- **Bidirectional NAT**: Adding a DNAT rule automatically creates a reverse
  SNAT static policy mapping (replace -> match), ensuring return traffic from
  the internal host is correctly translated back to the original destination.

**Special cases:**

- **Address conflict checks**: Adding fails with **EADDRINUSE** if the match
  address already has a nexthop in the VRF, or **EEXIST** if a DNAT rule
  already exists for that address. The **exist_ok** flag allows re-adding
  identical rules without error.

# SYNOPSIS

**grcli** **dnat44** **add** **interface** _INTERFACE_ **destination** _DEST_
**replace** _REPLACE_ [**vrf** _VRF_]

**grcli** **dnat44** **del** **interface** _INTERFACE_ **destination** _DEST_
[**vrf** _VRF_]

**grcli** **dnat44** **show** [**vrf** _VRF_]

# ARGUMENTS

_INTERFACE_
    Interface name where the DNAT rule applies. The server resolves this to
    an interface ID and uses the interface's VRF for the routing table
    lookup. The interface must exist or the operation fails with **ENODEV**.

_DEST_
    Destination IP address to match (e.g., 172.16.0.99). **Only IPv4
    addresses are supported, no ports.** The server checks if this address
    already has a nexthop in the VRF (**EADDRINUSE** error) or a DNAT rule
    (**EEXIST** error). A /32 route is created for this address.

_REPLACE_
    Replacement IP address (e.g., 10.99.0.99). **Only IPv4 addresses are
    supported, no ports.** This is where matching traffic will be
    redirected. The reverse SNAT policy uses this as the "public" address
    for return traffic.

_VRF_
    VRF ID for the DNAT rule (optional). Currently used for filtering in
    the list command. The VRF is implicitly determined by the interface for
    add/del operations.

# EXAMPLES

Add DNAT rules to redirect traffic:

```
dnat44 add interface gi3tem0 destination 172.16.0.99 replace 10.99.0.99
```

Display current DNAT rules:

```
dnat44 show
```

Remove a DNAT rule:

```
dnat44 del interface gi3tem0 destination 172.16.0.99
```

Example output:

```
grout# dnat44 show
INTERFACE  DESTINATION  REPLACE
gi3tem0    172.16.0.99  10.99.0.99
```

# SEE ALSO

**grcli**(1), **grcli-address**(1)

# AUTHORS

Created and maintained by Robin Jarry.
