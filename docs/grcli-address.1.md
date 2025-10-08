GRCLI-ADDRESS 1 @DATE@ "grout @VERSION@"
========================================

# NAME

**grcli-address** -- grout IP address management commands

# DESCRIPTION

The **address** commands manage IP addresses on grout interfaces, including
IPv4 and IPv6 address assignment, removal, and display.

These commands send **GR_IP4_ADDR_ADD**, **GR_IP4_ADDR_DEL**,
**GR_IP6_ADDR_ADD**, or **GR_IP6_ADDR_DEL** API requests to the grout daemon.
The address family (IPv4 or IPv6) is automatically detected from the address
format. When adding an address, the server creates a local nexthop, inserts
a connected route into the routing table (RIB), and triggers address add
events. For IPv6, the interface automatically joins the solicited-node
multicast group and link-local addresses are auto-configured from the MAC
address.

**Special cases:**

- **IPv6 link-local auto-config**: When a non-loopback interface is added,
  an fe80::/64 link-local address is automatically created from the interface
  MAC address. This happens automatically without requiring manual address
  configuration.
- **Interface deletion**: When an interface is removed, all associated IP
  addresses are automatically deleted, along with their routes and multicast
  group memberships. This cleanup happens via **GR_EVENT_IFACE_PRE_REMOVE**.
- **Loopback interfaces**: IPv6 link-local addresses are NOT auto-configured
  on loopback interfaces.

# SYNOPSIS

**grcli** **address** **add** _ADDR_ **iface** _IFACE_

**grcli** **address** **del** _ADDR_ **iface** _IFACE_

**grcli** **address** **show** [**iface** _IFACE_]

# ARGUMENTS

_ADDR_
    IP address with prefix length (e.g., 172.16.0.1/24, 2001::1/64). The
    prefix length is mandatory. The address format determines whether IPv4
    or IPv6 API requests are used. When adding, the server checks for
    duplicate addresses on the interface and verifies the address is not
    already in use in the VRF (**EADDRINUSE** error). The **exist_ok** flag
    allows adding duplicate addresses without error. When deleting, the
    **missing_ok** flag prevents errors if the address doesn't exist.

_IFACE_
    Interface name to assign the address to. The server resolves this to an
    interface ID before processing. If the interface doesn't exist, the
    operation fails with **ENODEV**.

# EXAMPLES

Add IPv4 and IPv6 addresses to interfaces:

```
address add 172.16.0.1/24 iface p0
address add 2001::1/64 iface p0
address add 10.99.0.1/24 iface p1
```

Remove an address from an interface:

```
address del 172.16.0.1/24 iface p0
```

Display all addresses or addresses for a specific interface:

```
address show
address show iface p0
```

Example output:

```
grout# address show
IFACE    ADDRESS
p0       172.16.0.1/24
p0       2001::1/64
p1       10.99.0.1/24
p1       2001:db8::1/64
p2       192.168.1.1/24
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
