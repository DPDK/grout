# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: SRv6 transit (End)
#
# IPv6 packets carrying an SRH whose active segment is one of grout's local End
# SIDs, with one segment still left. The SRH segment list is stored in reverse on
# the wire, so addresses[0] is the next segment and addresses[1] is grout's SID
# (the current destination). grout runs End: Segments Left 1 -> 0, the outer
# destination becomes the next segment, and the packet is forwarded out the
# opposite port. The two directions use different SIDs and next segments.
#
# Ether(14) + IPv6(40) + SRH(8 + 2*16) + UDP(8) = 102 bytes on the wire.
# An STLVM sweeps the UDP source port to spread the traffic over many flows.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

# grout local End SIDs (one per ingress direction).
SID_P0 = "fd00:e0::1"  # processed for traffic entering on p0
SID_P1 = "fd00:e1::1"  # processed for traffic entering on p1

# Next segments, behind the opposite port.
NEXT_P0 = "fd00:100::1"  # reachable via p0
NEXT_P1 = "fd00:200::1"  # reachable via p1

FRAME_SIZE = 60


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


class Profile:
    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            eth = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            src, sid, nxt = NEXT_P0, SID_P0, NEXT_P1
        else:
            eth = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            src, sid, nxt = NEXT_P1, SID_P1, NEXT_P0

        pkt = eth / IPv6(src=src, dst=sid)
        pkt /= IPv6ExtHdrSegmentRouting(addresses=[nxt, sid], segleft=1)
        pkt /= UDP(sport=1024, dport=1024, chksum=0)
        pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"

        return [
            STLStream(packet=STLPktBuilder(pkt=pkt, vm=sport_vm()), mode=STLTXCont())
        ]


def register():
    return Profile()
