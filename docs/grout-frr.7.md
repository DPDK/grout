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

## 2. FRR Configuration Overview

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
exit
!
end
```

Two additional configurations for a neighbor are required:
- source interface, `gr-loop0`, only required for the default VRF
- update source IP, local Grout IP

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
Updated by Maxime Leroy
