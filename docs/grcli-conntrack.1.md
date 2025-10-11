GRCLI-CONNTRACK 1 @DATE@ "grout @VERSION@"
==========================================

# NAME

**grcli-conntrack** -- grout connection tracking commands

# DESCRIPTION

The **conntrack** commands manage connection tracking in grout,
including viewing active connections, configuring timeouts, and
managing connection state.

# SYNOPSIS

**grcli** **conntrack** [**show**]

**grcli** **conntrack** **flush**

**grcli** **conntrack** **config** [**show**]

**grcli** **conntrack** **config** **set** [**max** _MAX_]
[**closed-timeout** _CLOSED_] [**new-timeout** _NEW_]
[**established-udp-timeout** _EST_UDP_] [**established-tcp-timeout** _EST_TCP_]
[**half-close-timeout** _HALF_CLOSE_] [**time-wait-timeout** _TIME_WAIT_]

# ARGUMENTS

_MAX_
    Maximum number of connections to track.

_CLOSED_
    Timeout for closed connections (seconds).

_NEW_
    Timeout for new connections (seconds).

_EST_UDP_
    Timeout for established UDP connections (seconds).

_EST_TCP_
    Timeout for established TCP connections (seconds).

_HALF_CLOSE_
    Timeout for half-closed connections (seconds).

_TIME_WAIT_
    Timeout for TIME_WAIT state connections (seconds).

# EXAMPLES

Display active connections:

```
conntrack show
```

Flush all connection entries:

```
conntrack flush
```

Display connection tracking configuration:

```
conntrack config show
```

Configure connection tracking parameters:

```
conntrack config set max 1024 closed-timeout 2
conntrack config set max 2048 established-tcp-timeout 3600
conntrack config set new-timeout 60 established-udp-timeout 1800
```

Example output:

```
grout# conntrack show
IFACE          ID  STATE        FLOW  SRC         DST         PROTO  SPORT  DPORT  LAST_UPDATE
p0     0x5caefe40  closed       fwd   10.99.0.99  172.16.0.2  TCP    55828   1234            0
                                rev   172.16.0.2  172.16.0.1          1234  21373
p0     0x5caeff00  established  fwd   10.99.0.99  172.16.0.2  UDP    37778   1234            0
                                rev   172.16.0.2  172.16.0.1          1234  28265

grout# conntrack config show
used 2 (0.2%)
max 1024
closed-timeout 2
new-timeout 5
established-udp-timeout 30
established-tcp-timeout 300
half-close-timeout 120
time-wait-timeout 30
```

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
