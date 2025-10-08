GRCLI-ADDRESS 1 @DATE@ "grout @VERSION@"
========================================

# NAME

**grcli-address** -- grout IP address management commands

# DESCRIPTION

The **address** commands manage IP addresses on grout interfaces, including
IPv4 and IPv6 address assignment, removal, and display.

# SYNOPSIS

**grcli** **address** **add** _ADDR_ **iface** _IFACE_

**grcli** **address** **del** _ADDR_ **iface** _IFACE_

**grcli** **address** **show** [**iface** _IFACE_]

# ARGUMENTS

_ADDR_
    IP address with prefix length (e.g., 172.16.0.1/24, 2001::1/64).

_IFACE_
    Interface name to assign the address to.

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
