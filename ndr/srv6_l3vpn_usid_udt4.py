# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: SRv6 L3VPN, uSID uDT4 (H.Encaps.Red / uN + End.DT4)
#
# Asymmetric SRv6 L3VPN profile exercising uSID (RFC 9800) encapsulation and the
# uDT4 egress. Locator block 32 bits, CSID 16 bits.
#   direction 0 (TRex port 0 -> grout p0): plain IPv4 packet toward the remote
#     site; grout H.Encaps.Red-encapsulates it into the remote uSID container
#     (fd00:b:100:200::), no SRH, out p1;
#   direction 1 (TRex port 1 -> grout p1): a uSID packet destined to grout's
#     container (fd00:a:100:200::) with an inner IPv4 packet; grout runs uN (shift
#     to fd00:a:200::) then uDT4 (decapsulate + IPv4 FIB lookup) and routes the
#     inner IPv4 out p0.
#
# Ingress direction 0 is a 64-byte IPv4 frame; ingress direction 1 is
# Ether(14) + IPv6(40) + IPv4(20) + UDP(8) = 82 bytes (uSID, no SRH).
# An STLVM sweeps the UDP source port to spread the traffic over many flows.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

# Customer IPv4 hosts: local (behind p0) and remote (behind the uSID tunnel).
LOCAL_HOST = "16.0.0.1"
REMOTE_HOST = "48.0.0.1"

# IPv6 underlay peer and grout's local uSID container (block 32, CSID 16):
# uN 0100 followed by uDT4 0200.
UNDERLAY_PEER = "fd00:1::2"
GROUT_USID = "fd00:a:100:200::"

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
            # uSID packet (no SRH): destination is grout's container, inner IPv4.
            pkt = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            pkt /= IPv6(src=UNDERLAY_PEER, dst=GROUT_USID)
            pkt /= IP(src=REMOTE_HOST, dst=LOCAL_HOST)
            pkt /= UDP(sport=1024, dport=1024, chksum=0)

        return [
            STLStream(packet=STLPktBuilder(pkt=pkt, vm=sport_vm()), mode=STLTXCont())
        ]


def register():
    return Profile()
