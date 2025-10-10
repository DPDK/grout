GRCLI-EVENTS 1 @DATE@ "grout @VERSION@"
=======================================

# NAME

**grcli-events** -- grout event subscription and monitoring commands

# DESCRIPTION

The **events** command provides real-time event monitoring capabilities in
grout, allowing you to subscribe to and monitor various system events such as
interface changes, route updates, nexthop modifications, and configuration
changes.

The command subscribes to all available events and displays them in real-time
with a "> " prompt prefix. Events are printed using registered event printers
for different event types.

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
