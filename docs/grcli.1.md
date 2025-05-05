GRCLI 1 @DATE@ "grout @VERSION@"
================================

# NAME

**grcli** -- grout command line interface

# DESCRIPTION

Grout is a software router based on DPDK __rte_graph__.

# SYNOPSIS

**grcli**
[**-e**]
[**-f** _PATH_]
[**-h**]
[**-s** _PATH_]
[**-V**]
[**-x**]
...

# OPTIONS

#### **-e**, **--err-exit**

Abort on first error.

#### **-f** _PATH_, **--file** _PATH_

Read commands from _PATH_ instead of standard input.

#### **-h**, **--help**

Show this help message and exit.

#### **-s** _PATH_, **--socket** _PATH_

Path to the control plane API socket.

Default: **GROUT_SOCK_PATH** from environment or _/run/grout.sock_.

#### **-V**, **--version**

Print version and exit.

#### **-x**, **--trace-commands**

Print executed commands.

# ENVIRONMENT

#### **DPRC**

Set the DPRC - Datapath Resource Container: This value should match the
one used by DPDK during the scan of the fslmc bus. It is recommended to
set this on any NXP QorIQ targets. This serves as the entry point for
grcli to enable autocompletion of fslmc devices manageable by grout.
While grcli can configure grout without this environment setting,
autocompletion of the devargs will not be available.

# SEE ALSO

**grout**(8)

# AUTHORS

Created and maintained by Robin Jarry.
