GRCLI-EVENTS 1 @DATE@ "grout @VERSION@"
=======================================

# NAME

**grcli-events** -- grout event subscription and monitoring commands

# DESCRIPTION

The **events** command provides real-time event monitoring capabilities in
grout, allowing you to subscribe to and monitor various system events such as
interface changes, route updates, nexthop modifications, and configuration
changes.

The command sends a **GR_MAIN_EVENT_SUBSCRIBE** API request with
**EVENT_TYPE_ALL** to subscribe to all available event types. The server
registers the client socket in its event distribution system and streams events
as they occur. Events are received via **gr_api_client_event_recv** and
displayed in real-time with a "> " prompt prefix. Each event type has a
registered printer function that formats the event data for display. When the
command terminates (via Ctrl+C or quit), a **GR_MAIN_EVENT_UNSUBSCRIBE**
request is sent to clean up the subscription.

**Note:**

- **Real-time streaming**: Events are pushed from the server immediately as
  they occur, providing instant visibility into system state changes.
- **All event types**: Subscribes to all available event types including
  interface events (GR_EVENT_IFACE_POST_ADD, GR_EVENT_IFACE_STATUS_UP, etc.),
  nexthop events (GR_EVENT_NEXTHOP_NEW, GR_EVENT_NEXTHOP_UPDATE, etc.), IPv4
  address/route events, and IPv6 address/route events.
- **Self-events**: The suppress_self_events flag is hardcoded to false,
  meaning you will see events triggered by your own API commands. This is
  useful for debugging and understanding command effects.

# SYNOPSIS

**grcli** **events** [**show**]

# ARGUMENTS

**show**
    Optional keyword to explicitly show events. This is the default behavior
    when no arguments are provided.

# EXAMPLES

Start real-time event monitoring:

```
events
events show
```

Both commands are equivalent and will start real-time event monitoring.

Example output:

```
> iface add: p0 type=port id=257 vrf=0 mtu=1500
> iface up: p0 type=port id=257 vrf=0 mtu=1500
> nh new: type=L3 id=42 iface=257 vrf=0 origin=user af=IPv4 addr=1.2.3.4 state=new
> addr add: iface=257 10.0.0.1/24
> nh del: type=L3 id=42 iface=257 vrf=0 origin=user af=IPv4 addr=1.2.3.4 state=new
> iface down: p0 type=port id=257 vrf=0 mtu=1500
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
