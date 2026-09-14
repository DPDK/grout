# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: SRv6 L3VPN (H.Encaps / End.DT4)
#
# Asymmetric SRv6 L3VPN profile (modeled on smoke/srv6_test.sh):
#   direction 0 (TRex port 0 -> grout p0): plain IPv4 packet toward the remote
#     site; grout H.Encaps it into SRv6 and sends the IPv6 packet out p1;
#   direction 1 (TRex port 1 -> grout p1): SRv6 packet destined to grout's local
#     End.DT4 SID with an inner IPv4 packet; grout decapsulates and routes the
#     inner IPv4 out p0.
#
# Ingress direction 0 is a 64-byte IPv4 frame; ingress direction 1 is
# Ether(14) + IPv6(40) + SRH(8 + 16) + IPv4(20) + UDP(8) = 106 bytes.
# An STLVM sweeps the UDP source port to spread the traffic over many flows.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

# Customer IPv4 hosts: local (behind p0) and remote (behind the SRv6 tunnel).
LOCAL_HOST = "16.0.0.1"
REMOTE_HOST = "48.0.0.1"

# IPv6 underlay: peer on the core side and grout's local End.DT4 SID.
UNDERLAY_PEER = "fd00:1::2"
GROUT_SID = "fd00:a::1"

FRAME_SIZE = 60


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


class Profile:
    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            # Plain customer IPv4 toward the remote site; grout encapsulates it.
            pkt = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            pkt /= IP(src=LOCAL_HOST, dst=REMOTE_HOST)
            pkt /= UDP(sport=1024, dport=1024, chksum=0)
            pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"
        else:
            # SRv6 traffic to grout's End.DT4 SID with an inner IPv4 packet.
            pkt = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            pkt /= IPv6(src=UNDERLAY_PEER, dst=GROUT_SID)
            pkt /= IP(src=REMOTE_HOST, dst=LOCAL_HOST)
            pkt /= UDP(sport=1024, dport=1024, chksum=0)

        return [
            STLStream(packet=STLPktBuilder(pkt=pkt, vm=sport_vm()), mode=STLTXCont())
        ]


def register():
    return Profile()
