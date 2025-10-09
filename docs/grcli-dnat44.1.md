GRCLI-DNAT44 1 @DATE@ "grout @VERSION@"
=======================================

# NAME

**grcli-dnat44** -- grout destination NAT (DNAT) configuration commands

# DESCRIPTION

The **dnat44** commands configure static destination NAT rules in grout,
allowing incoming traffic to be redirected to different internal addresses
and ports.

# SYNOPSIS

**grcli** **dnat44** **add** _INTERFACE_ **destination** _DEST_
**replace** _REPLACE_ [**vrf** _VRF_]

**grcli** **dnat44** **del** _INTERFACE_ **destination** _DEST_
[**vrf** _VRF_]

**grcli** **dnat44** **show** [**vrf** _VRF_]

# ARGUMENTS

_INTERFACE_
    Interface name where the DNAT rule applies.

_DEST_
    Destination IP address to match (e.g., 172.16.0.99).

_REPLACE_
    Replacement IP address (e.g., 10.99.0.99).

_VRF_
    VRF ID for the DNAT rule (optional).

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
