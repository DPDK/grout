GRCLI-LOGGING 1 @DATE@ "grout @VERSION@"
========================================

# NAME

**grcli-logging** -- grout packet logging commands

# DESCRIPTION

The **logging** commands control real-time packet logging in grout, allowing
you to enable or disable logging of ingress and egress packets for debugging
and monitoring purposes.

These commands send **GR_INFRA_PACKET_LOG_SET** or
**GR_INFRA_PACKET_LOG_CLEAR** API requests. When enabled, the server sets the
global `gr_config.log_packets` flag to true. This causes the datapath to log
detailed packet information for every packet received on RX queues, every
packet transmitted on TX queues, packets sent/received on loopback interfaces,
and packets dropped by error nodes. The logging uses the `trace_log_packet`
function which formats packets in human-readable form showing source/destination
MAC addresses, IP addresses, protocol types (TCP/UDP/ICMP), port numbers, and
packet length. STP (Spanning Tree Protocol) packets are filtered to reduce
noise.

**Note:**

- **Performance impact**: Packet logging generates a log message for EVERY
  packet in the system with decoded protocol information. This significantly
  impacts performance and generates large amounts of log output. Only enable
  for debugging and disable immediately after.
- **System-wide flag**: This is a global flag affecting all interfaces and all
  workers. There is no per-interface or per-queue granularity.
- **Log destination**: Packets are logged via grout's logging system, which by
  default writes to syslog (see **grout**(8) `-S` option) or stderr. The log
  level is NOTICE for drop events and DEBUG for RX/TX events.
- **STP filtering**: 802.1D Spanning Tree Protocol packets (destination MAC
  01:80:c2:00:00:00) are automatically filtered and not logged to reduce noise
  from protocol keepalives.

**Special cases:**

- **Can be enabled at startup**: The `-x` option to **grout**(8) enables
  packet logging at daemon startup, equivalent to running `logging enable`
  immediately after startup.
- **No state persistence**: The logging state is not persisted. If grout is
  restarted, logging reverts to disabled (unless `-x` was used).

# SYNOPSIS

**grcli** **logging** **enable**

**grcli** **logging** **disable**

# EXAMPLES

Enable packet logging for debugging:

```
logging enable
```

Disable packet logging after debugging:

```
logging disable
```

When enabled, log output will show packet details like:

```
NOTICE: GROUT: trace_log_packet: [rx p0] f0:0d:ac:dc:00:00 > 33:33:00:00:00:02 / IPv6 fe80::d868:baff:fec8:61e6 > ff02::2 ttl=255 proto=ICMPv6(58) / ICMPv6 router solicit / Option src_lladdr=f0:0d:ac:dc:00:00, (pkt_len=70)
NOTICE: GROUT: trace_log_packet: [tx p0] f0:0d:ac:dc:00:00 > 33:33:00:00:00:01 / IPv6 fe80::f00d:acff:fedc:0 > ff02::1 ttl=255 proto=ICMPv6(58) / ICMPv6 router advert / Option src_lladdr=f0:0d:ac:dc:00:00, (pkt_len=78)
NOTICE: GROUT: trace_log_packet: [rx gr-loop0] 8a:9d:b1:07:33:16 > 33:33:00:00:00:fb / IPv6 fe80::889d:b1ff:fe07:3316 > ff02::fb ttl=255 proto=UDP(17), (pkt_len=222)
```

# SEE ALSO

**grcli**(1), **grout**(8)

# AUTHORS

Created and maintained by Robin Jarry.
