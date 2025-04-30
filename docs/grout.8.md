GROUT 8 @DATE@ "grout @VERSION@"
================================

# NAME

**grout** -- graph router daemon

# DESCRIPTION

Grout is a software router based on DPDK __rte_graph__.

# SYNOPSIS

**grout**
[**-B** _SIZE_]
[**-D** _PATH_]
[**-h**]
[**-L** _TYPE_:_LEVEL_]
[**-M** _MODE_]
[**-m** _PERMISSIONS_]
[**-o** _USER_:_GROUP_]
[**-p**]
[**-S**]
[**-s** _PATH_]
[**-t**]
[**-T** _REGEXP_]
[**-v**]
[**-V**]
[**-x**]

# OPTIONS

#### **-B**, **--trace-bufsz** _SIZE_

Specify maximum size of allocated memory for trace output for each thread.
Valid unit can be either B or K or M for Bytes, KBytes and MBytes respectively.
For example:

```
--trace-bufsz 2M
```

By default, size of trace output file is 1MB and parameter must be
specified once only.

#### **-D**, **--trace-dir** _PATH_

Specify trace directory for trace output. For example:

```
--trace-dir /tmp
```

By default, trace output will created at home directory and parameter must be
specified once only.

#### **-h**, **--help**

Display usage help.

#### **-L**, **--log-level** _TYPE_:_LEVEL_

Specify log level for a specific component. For example:

```
--log-level lib.eal:debug
```

Can be specified multiple times.

#### **-M**, **--trace-mode** _o_|_overwrite_|_d_|_discard_

Specify the mode of update of trace output file. Either update on a file can be
wrapped or discarded when file size reaches its maximum limit. For example:

```
--trace-mode discard
```

Default mode is _overwrite_ and parameter must be specified once only.

#### **-m**, **--socket-mode** _PERMISSIONS_

Change the API socket file permissions after creating it. Only octal values are
supported.

Default: _0660_.

#### **-o**, **--socket-owner** _USER_:_GROUP_

Change the owner of the API socket file after creating it. Symbolic names and
numeric IDs are supported.

Default: current user and current group.

#### **-p**, **--poll-mode**

Disable automatic micro-sleep.

#### **-S**, **--syslog**

Redirect logs to syslog.

#### **-s**, **--socket** _PATH_

Path the control plane API socket.

Default: **GROUT_SOCK_PATH** from environment or _/run/grout.sock_.

#### **-t**, **--test-mode**

Run in test mode (no huge pages).

#### **-T**, **--trace** _REGEXP_

Enable trace based on regular expression trace name. By default, the trace is
disabled. User must specify this option to enable trace. For example:

Global trace configuration for EAL only:

```
--trace eal
```

Global trace configuration for ALL the components:

```
--trace ".*"
```

Can be specified multiple times up to 32 times.

#### **-v**, **--verbose**

Increase verbosity. Can be specified multiple times.

#### **-V**, **--version**

Print version and exit.

#### **-x**, **--trace-packets**

Print all ingress/egress packets (for debugging purposes).

# SEE ALSO

**grcli**(1)

# AUTHORS

Created and maintained by Robin Jarry.
