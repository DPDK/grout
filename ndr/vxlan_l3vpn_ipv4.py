# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: VXLAN L3VPN, IPv4 underlay
#
# Asymmetric L3VPN profile with an IPv4 underlay:
#
#   direction 0 (TRex port 0 -> grout p0): VXLAN frame whose inner Ethernet is
#     addressed to grout's local RMAC; grout decaps, routes the inner IPv4
#     packet toward the customer subnet and sends it plain out p1;
#
#   direction 1 (TRex port 1 -> grout p1): plain IPv4 packet toward the overlay
#     subnet; grout routes it to the remote next hop and VXLAN-encaps it out p0.
#
# The routed customer packet is 64 bytes on the wire in both directions; the
# encapsulated frame adds the outer Ethernet/IP/UDP/VXLAN headers (~114 bytes).
#
# Flow spreading (both are source UDP ports, one per emulated client):
#   - decap direction: the outer VXLAN UDP source port is swept (the RSS key on
#     grout's receive side). grout does not verify the outer UDP checksum over an
#     IPv4 underlay, so it is left zero and the swept port needs no recompute.
#     Hardware checksum offload is deliberately not used here: on real NICs it
#     corrupts the inner IPv4 header checksum of the tunneled frame;
#   - encap direction: the customer UDP source port is swept; grout derives the
#     outer VXLAN source port from the inner flow hash, so this spreads the
#     encapsulated traffic on the wire.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

# Underlay VTEP addresses.
LOCAL_VTEP = "172.16.0.1"
REMOTE_VTEP = "172.16.0.2"
VNI = 100

# Overlay router MACs (RMAC): grout's own L3VNI RMAC and the remote VTEP's RMAC.
LOCAL_RMAC = "02:00:00:00:0b:00"
REMOTE_RMAC = "02:00:00:00:0b:01"

# Routed hosts: overlay subnet (behind tunnel) and customer subnet (behind p1).
OVERLAY_HOST = "16.0.0.1"
CUSTOMER_HOST = "48.0.0.1"

FRAME_SIZE = 60


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


def routed_frame(eth, src_ip, dst_ip):
    pkt = eth / IP(src=src_ip, dst=dst_ip) / UDP(sport=1024, dport=1024, chksum=0)
    pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"
    return pkt


class Profile:
    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            # Inner frame addressed to grout's local RMAC so it routes after decap.
            pkt = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            pkt /= IP(src=REMOTE_VTEP, dst=LOCAL_VTEP)
            pkt /= UDP(sport=1024, dport=4789, chksum=0)  # not verified over IPv4
            pkt /= VXLAN(vni=VNI, flags=0x08)
            pkt /= routed_frame(
                Ether(src=REMOTE_RMAC, dst=LOCAL_RMAC), OVERLAY_HOST, CUSTOMER_HOST
            )
            vm = sport_vm()
        else:
            # Plain routed packet toward the overlay subnet.
            pkt = routed_frame(
                Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC), CUSTOMER_HOST, OVERLAY_HOST
            )
            vm = sport_vm()

        return [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())]


def register():
    return Profile()
