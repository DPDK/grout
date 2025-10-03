GROUT-FRR 7 @DATE@ "grout @VERSION@"
================================

# FRR + Grout: Transparent BGP Peering via Loopback Interfaces

This guide demonstrates how to configure FRR (Free Range Routing) and Linux networking to establish BGP peering
between Grout and an upstream router, without assigning IP addresses directly to the Linux interface.

0. Context
1. How packets are forwarded from Grout to `gr-loop0`
2. Linux configuration to peer without adding a local ip
3. BGPD configuration
---

## 0. Ease of Use

By default, FRR daemons such as `bgpd` require binding to a local IP address to accept incoming peer connections.
This necessitates explicitly adding all Grout "local" IPs to the `gr-loop0` interface.
However, this approach is cumbersome and not ideal.

The objective is to run `bgpd` without assigning any IP address to the `gr-loop0` network device.
This is achieved by utilizing the `IP_TRANSPARENT` socket option and FRR's capability to bind to a specific interface.

---

## 1. Packets from grout to gr-loop0

All packets received to a **local** IP configured in grout will be processed by the node `ip_input_local/ip6_input_local`.
If the protocol isn't handled locally (ICMP, Neighbor Disc, ...), the packets are forwarded to `l4_input_local`.
If still unhandled (e.g., VXLAN Tunnel), the packet is sent to the corresponding `gr-loopX` interface associated with the VRF.

---

## 2. Linux configuration

To ensure all incoming packets from `gr-loop0` are accepted by the network stack, execute the following commands:
```sh
a) sysctl -w net.ipv4.conf.gr-loop0.rp_filter=0
b) iptables -t mangle -A PREROUTING -i gr-loop0 -j MARK --set-mark 0x1
c) ip rule add fwmark 0x1 lookup 42
d) ip route add local default dev gr-loop0 table 42
```
a) Disables Reverse Path Filtering
b) All packets received on the `gr-loop0` interface will have a specific mark
c) based on this mark, lookup on a specific table
d) accept ALL packets as if the destination was local.
While we could mark only the packets matching the TCP port 179 (for BGP), we accept all packets for other applications.

This can be automated with the following udev rules, and the proper `sysctl` config:

```sh
# /etc/udev/rules.d/99-gr-loop0.rules
ACTION=="add", KERNEL=="gr-loop0", RUN+="/usr/sbin/iptables -t mangle -A PREROUTING -i gr-loop0 -j MARK --set-mark 0x1"
ACTION=="add", KERNEL=="gr-loop0", RUN+="/usr/sbin/ip route replace local default dev gr-loop0 table 42"
ACTION=="add", KERNEL=="gr-loop0", RUN+="/usr/sbin/ip rule add fwmark 0x1 lookup 42 priority 42"

ACTION=="remove", KERNEL=="gr-loop0", RUN+="/usr/sbin/ip route del table 42 local default dev gr-loop0"
ACTION=="remove", KERNEL=="gr-loop0", RUN+="/usr/sbin/ip rule del fwmark 0x1 lookup 42 priority 42"
ACTION=="remove", KERNEL=="gr-loop0", RUN+="/usr/sbin/iptables -t mangle -D PREROUTING -i gr-loop0 -j MARK --set-mark 0x1"
```

```sh
# cat /etc/sysctl.d/10-grout.conf
net.ipv4.conf.gr-loop0.rp_filter = 0
```

---

## 3. FRR Configuration Overview

Zebra must be run with the `-M` option to load the plugin:
Edit the file `/etc/frr/daemons`, for example:

```ini
zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_grout"
```

```frr
service integrated-vtysh-config
!
interface cv0
 ip address 192.168.210.1/24
exit
!
router bgp 64513
 neighbor 192.168.210.3 remote-as 64513
 neighbor 192.168.210.3 interface gr-loop0
 neighbor 192.168.210.3 update-source 192.168.210.1
 neighbor 192.168.210.3 ip-transparent
exit
!
end
```

Note: The `IP_TRANSPARENT` socket option and FRR's BGP `neighbor <peer> ip-transparent` are supported
only if the Linux kernel provides `IP_TRANSPARENT` and FRRouting supports the feature (added in FRR 10.4.0).
The FRR daemon must run with sufficient network privileges to create raw/non‑local sockets and manage routing
(for example, `CAP_NET_ADMIN` and `CAP_NET_RAW`), which shouldn't be an issue.

Three additional configuration for a neighbor is required:
- source interface, `gr-loop0`, only required for the default VRF
- update source IP, local Grout IP
- ip-transparent, to allow `bgpd` to bind on the non existent IP.

With that configuration, BGP messages are properly exchanged, and routes are visible in grout:

```frr
vtysh# show bgp summary

IPv4 Unicast Summary:
BGP router identifier 192.168.211.0, local AS number 64513 VRF default vrf-id 0
BGP table version 15
RIB entries 28, using 3584 bytes of memory
Peers 2, using 47 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
192.168.210.3   4      64513        50        48       15    0    0 00:43:31           14        2 N/A

Total number of neighbors 1
```

```grout
grout# route show
VRF  DESTINATION        NEXT_HOP
0    192.168.1.0/24     type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.2.0/24     type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.11.254/32  type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.11.0/24    type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.20.0/24    type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.94.0/24    type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.95.0/24    type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.200.0/24   type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.201.0/24   type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.203.0/24   type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.210.0/24   type=L3 iface=p0 vrf=0 origin=link af=IPv4 addr=192.168.210.1/24 mac=f0:0d:ac:dc:00:00 static local link
0    192.168.211.0/24   type=L3 iface=p1 vrf=0 origin=link af=IPv4 addr=192.168.211.1/24 mac=f0:0d:ac:dc:00:01 static local link
0    192.168.239.0/24   type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.254.0/24   type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
0    192.168.255.10/32  type=L3 id=10 iface=p0 vrf=0 origin=bgp af=IPv4 addr=192.168.210.3 state=new
```

# AUTHORS

Created by Christophe Fontaine
