GRCLI-SNAT44 1 @DATE@ "grout @VERSION@"
=======================================

# NAME

**grcli-snat44** -- grout source NAT (SNAT) configuration commands

# DESCRIPTION

The **snat44** commands configure dynamic source NAT policies in grout,
allowing outgoing traffic from internal subnets to be translated to different
external IP addresses.

These commands send **GR_SNAT44_ADD**, **GR_SNAT44_DEL**, or
**GR_SNAT44_LIST** API requests. When adding a policy, the server creates port
and ICMP ID pools for TCP (1024-65535), UDP (1024-65535), and ICMP (1-65535),
sets the interface SNAT_DYNAMIC flag, and stores the policy for connection
tracking. Outgoing connections matching the source subnet are automatically
assigned translated ports/IDs from the pools. Return traffic is correctly
routed back through reverse connection tracking entries.

When deleting a policy, the server waits for RCU grace period to ensure no
datapath workers are using the policy, purges all associated connections from
the connection tracking table, destroys the port/ID pools, and clears the
interface flag if no other SNAT policies remain on that interface.

**Note:**

- **Dynamic port allocation**: For each new outgoing connection, a random
  available port (TCP/UDP) or ICMP identifier is allocated from the policy's
  pool. Ports 1024-65535 are used for TCP/UDP, IDs 1-65535 for ICMP.
- **Automatic connection tracking**: SNAT policies work with connection
  tracking to maintain bidirectional state. Forward flows use original source
  addresses, reverse flows use translated addresses.
- **Replace address reachability**: The replace address must already have a
  nexthop in the interface's VRF or the operation fails with
  **EADDRNOTAVAIL**. This ensures the translated address is routable.
- **Per-interface policies**: Each interface can have multiple SNAT policies
  with different source subnets. Policies are matched by checking if the
  packet's source IP falls within any configured subnet for that interface.
- **Port exhaustion handling**: When all ports in a pool are allocated, new
  connections from that source subnet cannot be established until existing
  connections close and release their ports.

**Special cases:**

- **RCU synchronization on deletion**: When deleting a policy, the server uses
  RCU synchronization to ensure all datapath workers finish processing packets
  before freeing the policy memory and port pools.
- **Connection purging**: Deletion purges all existing connections associated
  with the policy, freeing allocated ports back to the pools before destroying
  them.
- **Interface flag management**: The GR_IFACE_F_SNAT_DYNAMIC flag is set when
  the first policy is added to an interface and cleared when the last policy
  is removed, allowing efficient datapath checks.
- **Subnet overlap**: Multiple policies with overlapping subnets on the same
  interface are allowed. The first matching policy (based on insertion order)
  is used for a given connection.
- **Duplicate policy handling**: Adding an identical policy (same interface,
  subnet, and replace address) fails with **EEXIST** unless **exist_ok** flag
  is set, which makes it succeed silently.

# SYNOPSIS

**grcli** **snat44** **add** **interface** _IFACE_ **subnet** _NET_ **replace**
_REPLACE_

**grcli** **snat44** **del** **interface** _IFACE_ **subnet** _NET_ **replace**
_REPLACE_

**grcli** **snat44** [**show**]

# ARGUMENTS

_IFACE_
    Output interface name where the SNAT policy applies. The server resolves
    this to an interface ID and uses the interface's VRF to verify the
    replace address is reachable. The interface must exist or the operation
    fails with **ENODEV**.

_NET_
    Source IP subnet (IPv4 only) for which to perform source NAT (e.g.,
    10.99.0.0/24). Packets with source addresses matching this subnet will
    have their source address and port/ID translated. The prefix length is
    mandatory.

_REPLACE_
    External IP address to use as the translated source address (e.g.,
    172.16.0.1). **Only IPv4 addresses are supported.** This address must
    have a reachable nexthop in the interface's VRF or the operation fails
    with **EADDRNOTAVAIL**.

# EXAMPLES

Add SNAT policy to translate outgoing traffic:

```
snat44 add interface p0 subnet 10.99.0.0/24 replace 172.16.0.1
```

Display all SNAT policies:

```
snat44 show
```

Remove a SNAT policy:

```
snat44 del interface p0 subnet 10.99.0.0/24 replace 172.16.0.1
```

Example output:

```
grout# snat44 show
INTERFACE  SUBNET         REPLACE
p0         10.99.0.0/24   172.16.0.1
```

# SEE ALSO

**grcli**(1), **grcli-dnat44**(1), **grcli-conntrack**(1), **grcli-interface**(1)

# AUTHORS

Created and maintained by Robin Jarry.
