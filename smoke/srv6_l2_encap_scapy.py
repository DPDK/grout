#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, IPv6ExtHdrSegmentRouting

# Interface where End.DX2 delivers Ethernet frames
IFACE = "veth0"
SR6IFACE = "x-p1"

# SRv6 parameters
SRC_IPV6 = "2001:db8:1::2"
SEGMENTS = ["5f00::"]    # SID list (last segment first per SRH rules)


def handle(pkt):
    if pkt.getlayer(IPv6ExtHdrSegmentRouting):
        return

    srh = IPv6ExtHdrSegmentRouting(
        segleft=len(SEGMENTS) - 1,
        addresses=SEGMENTS,
        nh = 143
    )

    outer_ip6 = IPv6(
        src=SRC_IPV6,
        dst=SEGMENTS[0]
    ) / srh / pkt

    sendp(Ether() / outer_ip6, iface=SR6IFACE, verbose=False)


sniff(iface=IFACE, prn=handle, store=False)
