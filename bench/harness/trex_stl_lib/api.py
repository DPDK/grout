# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# Minimal mock of the TRex stateless API (trex_stl_lib.api), sufficient to load
# the bench *.py profiles without a real TRex installation.
#
# TRex re-exports scapy, so the packet layers (Ether, Dot1Q, IP, IPv6, UDP,
# VXLAN, IPv6ExtHdrSegmentRouting, ...) come straight from scapy. The STL*
# helpers are reduced to thin holders: the harness only needs the base packet
# built by the profile, not the flow-variable engine, so the STLVM sweeps are
# accepted and ignored.

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import *
from scapy.layers.vxlan import *


class STLPktBuilder:
    def __init__(self, pkt=None, vm=None, **kwargs):
        self.pkt = pkt
        self.vm = vm


class STLStream:
    def __init__(self, packet=None, mode=None, isg=0, **kwargs):
        self.packet = packet
        self.mode = mode
        self.isg = isg


class STLTXCont:
    def __init__(self, *args, **kwargs):
        pass


class STLVM:
    # Fluent flow-variable engine. Ignored by the harness (a single base packet
    # is enough for a forwarding-sanity check), but the calls must chain.
    def var(self, *args, **kwargs):
        return self

    def tuple_var(self, *args, **kwargs):
        return self

    def write(self, *args, **kwargs):
        return self

    def fix_chksum(self, *args, **kwargs):
        return self

    def fix_chksum_hw(self, *args, **kwargs):
        return self


class CTRexVmInsFixHwCs:
    L4_TYPE_UDP = 11
    L4_TYPE_TCP = 13
