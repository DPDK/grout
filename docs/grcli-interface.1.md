GRCLI-INTERFACE 1 @DATE@ "grout @VERSION@"
==========================================

# NAME

**grcli-interface** -- grout interface management commands

# DESCRIPTION

The **interface** commands manage network interfaces in grout, including
physical ports, VLAN interfaces, and tunnel interfaces.

These commands send **GR_INFRA_IFACE_ADD**, **GR_INFRA_IFACE_SET**,
**GR_INFRA_IFACE_DEL**, **GR_INFRA_IFACE_GET**, or **GR_INFRA_IFACE_LIST**
API requests. When adding an interface, the server creates an internal iface
structure, assigns a unique interface ID, increments the VRF reference count,
registers the interface with the appropriate type handler (port, vlan, ipip),
and triggers **GR_EVENT_IFACE_POST_ADD**. When configuring ports, DPDK is used
to initialize the network device with specified devargs parameters. For VLAN
interfaces, the parent port must exist and the VLAN ID must be unique on that
parent. For IPIP tunnels, local and remote IPv4 addresses are required.

**Note:**

- **Automatic interface ID assignment**: Interface IDs 1-255 are reserved for
  loopback interfaces (one per VRF). Port, VLAN, and tunnel interfaces are
  assigned IDs starting from 256.
- **IPv6 link-local auto-configuration**: When a non-loopback interface is
  created and brought up, an fe80::/64 link-local address is automatically
  configured from the interface MAC address (see **grcli-address**(1)).
- **VRF reference counting**: Each interface increments its VRF reference
  count, preventing VRF deletion while interfaces exist in that VRF.
- **Interface cleanup on deletion**: When an interface is deleted, the server
  triggers **GR_EVENT_IFACE_PRE_REMOVE** to allow modules to clean up
  associated state (addresses, routes, nexthops, etc.) before the interface is
  destroyed.

**Special cases:**

- **Name collision**: Adding an interface with a name that already exists
  fails with **EEXIST**. Interface names are unique across all types.
- **VLAN parent must exist**: Adding a VLAN interface fails with **ENODEV** if
  the parent interface doesn't exist. The parent must be a port interface.
- **Duplicate VLAN ID**: Adding a VLAN with an ID that already exists on the
  same parent fails with **EEXIST**.
- **Interface in use**: Deleting an interface that has subinterfaces (e.g., a
  port with VLANs) or active routes may fail depending on cleanup order. Use
  **del** carefully and check for dependent resources first.

# SYNOPSIS

**grcli** **interface** **add** **port** _NAME_ **devargs** _DEVARGS_
[**mac** _MAC_] [**rxqs** _RXQ_] [**qsize** _SIZE_] [**vrf** _VRF_]
[**mtu** _MTU_] [**mode** **l3**|**xconnect** _PEER_] [**up**|**down**]
[**promisc** _BOOL_] [**allmulti** _BOOL_]

**grcli** **interface** **add** **vlan** _NAME_ **parent** _PARENT_
**vlan_id** _VLAN_ [**vrf** _VRF_] [**mtu** _MTU_] [**up**|**down**]
[**promisc** _BOOL_] [**allmulti** _BOOL_]

**grcli** **interface** **add** **ipip** _NAME_ **local** _LOCAL_
**remote** _REMOTE_ [**vrf** _VRF_] [**mtu** _MTU_] [**up**|**down**]

**grcli** **interface** **set** _NAME_ [**mac** _MAC_] [**rxqs** _RXQ_]
[**qsize** _SIZE_] [**vrf** _VRF_] [**mtu** _MTU_]
[**mode** **l3**|**xconnect** _PEER_] [**up**|**down**] [**promisc** _BOOL_]
[**allmulti** _BOOL_] [**name** _NEW_NAME_]

**grcli** **interface** **del** _NAME_

**grcli** **interface** **show** [_NAME_]

# ARGUMENTS

_NAME_
    Interface name (up to 63 characters). Must be unique across all interface
    types. The server validates UTF-8 encoding. Common naming conventions:
    "p0", "p1" for ports; "p0.42" for VLANs; "tun0" for tunnels.

_DEVARGS_
    DPDK device arguments string for port creation. Format depends on the
    DPDK driver. Examples: "net_tap0,iface=p0" for TAP interfaces,
    "0000:05:00.0" for PCI devices. See DPDK documentation for driver-specific
    options.

_MAC_
    Ethernet MAC address in colon-separated hexadecimal format (e.g.,
    f0:0d:ac:dc:00:00). For ports, this sets the hardware address. VLAN
    interfaces inherit the parent's MAC address.

_RXQ_
    Number of RX queues for the port (positive integer). More queues allow
    better multi-core load distribution. Must not exceed the device's
    capability. Default is typically 1.

_SIZE_
    RX/TX queue size (ring buffer size). Larger values provide more buffering
    but consume more memory. Must be a power of 2. Typical values: 512, 1024,
    2048.

_PARENT_
    Parent port interface name for VLAN subinterface. Must be an existing port
    interface. The server resolves this to an interface ID and creates a
    parent-child relationship.

_VLAN_
    802.1Q VLAN ID (1-4094). Must be unique on the specified parent interface.
    VLAN 0 is reserved, and 4095 is reserved for implementation use.

_LOCAL_
    Local endpoint IPv4 address for IPIP tunnel (e.g., 172.16.1.1). This is
    the source address for encapsulated packets.

_REMOTE_
    Remote endpoint IPv4 address for IPIP tunnel (e.g., 172.16.1.2). This is
    the destination address for encapsulated packets.

_VRF_
    VRF (Virtual Routing and Forwarding) domain ID (0-255). Default is 0 (the
    default VRF). All routing and address resolution for the interface happens
    within this VRF. The VRF must exist or the operation fails.

_MTU_
    Maximum Transmission Unit in bytes (typically 1500 for Ethernet). Includes
    IP header but not Ethernet header. Minimum is usually 68 bytes (IPv4) or
    1280 bytes (IPv6). The server may enforce driver-specific limits.

_PEER_
    Peer interface name for Layer 1 cross-connect mode. Traffic received on
    this interface is directly forwarded to the peer interface without any
    Layer 3 processing (no routing, no IP processing).

_BOOL_
    Boolean value: **true**, **false**, **on**, **off**, **yes**, **no**,
    **1**, or **0**.

_NEW_NAME_
    New interface name when using **set** command with **name** option. Must
    follow the same naming rules and uniqueness constraints as _NAME_.

**up**|**down**
    Administratively bring the interface up or down. When down, the interface
    stops processing packets. Sets or clears the **GR_IFACE_F_UP** flag.

**promisc**
    Enable or disable promiscuous mode. When enabled, the interface receives
    all packets regardless of destination MAC address. Useful for monitoring
    or bridging.

**allmulti**
    Enable or disable all-multicast mode. When enabled, the interface receives
    all multicast packets regardless of multicast group membership.

**mode**
    Interface operating mode: **l3** (Layer 3 routing, default) or
    **xconnect** (Layer 1 cross-connect to peer interface).

# EXAMPLES

Add physical port interfaces with TAP drivers:

```
interface add port p0 devargs net_tap0,iface=p0 mac f0:0d:ac:dc:00:00
interface add port p1 devargs net_tap1,iface=p1 mac f0:0d:ac:dc:00:01
```

Example output:

```
Created interface 257
Created interface 258
```

Add VLAN subinterfaces:

```
interface add vlan p0.42 parent p0 vlan_id 42
interface add vlan p1.43 parent p1 vlan_id 43
```

Add IPIP tunnel interface:

```
interface add ipip tun0 local 172.16.1.1 remote 172.16.1.2
```

Configure interface settings:

```
interface set p0 up promisc true mtu 9000
interface set p0 name p0-wan
```

Show all interfaces:

```
interface show
```

Example output:

```
NAME      ID   FLAGS                        MODE  DOMAIN  TYPE      INFO
gr-loop0  256  up running                   L3    0       loopback
p0        257  up running promisc allmulti  L3    0       port      devargs=net_tap0,iface=p0 mac=f0:0d:ac:dc:00:00
p1        258  up running promisc allmulti  L3    0       port      devargs=net_tap1,iface=p1 mac=f0:0d:ac:dc:00:01
```

Delete an interface:

```
interface del p0.42
```

# SEE ALSO

**grcli**(1), **grcli-address**(1)

# AUTHORS

Created and maintained by Robin Jarry.
