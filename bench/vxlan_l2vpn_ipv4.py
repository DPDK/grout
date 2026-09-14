# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: VXLAN L2VPN, IPv4 underlay
#
# Asymmetric L2VPN profile with an IPv4 underlay:
#   direction 0 (TRex port 0 -> grout p0): VXLAN frame, grout decaps and bridges
#     the inner Ethernet frame out the access port p1;
#   direction 1 (TRex port 1 -> grout p1): plain Ethernet frame, grout bridges it
#     into the tunnel and VXLAN-encaps it out p0.
#
# The inner customer frame is 64 bytes on the wire in both directions; the
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
TREX_P0_MAC = "02:00:00:00:01:00"

# Underlay VTEP addresses.
LOCAL_VTEP = "172.16.0.1"
REMOTE_VTEP = "172.16.0.2"
VNI = 100

# Inner customer hosts (MACs bridged across the tunnel).
REMOTE_HOST_MAC = "02:00:00:00:0c:00"  # behind the tunnel (TRex port 0 side)
LOCAL_HOST_MAC = "02:00:00:00:0c:01"  # behind the access port (TRex port 1 side)
REMOTE_HOST_IP = "16.0.0.1"
LOCAL_HOST_IP = "48.0.0.1"

FRAME_SIZE = 60


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


def inner_frame(src_mac, dst_mac, src_ip, dst_ip):
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip)
    pkt /= UDP(sport=1024, dport=1024, chksum=0)
    pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"
    return pkt


class Profile:
    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            pkt = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            pkt /= IP(src=REMOTE_VTEP, dst=LOCAL_VTEP)
            pkt /= UDP(sport=1024, dport=4789, chksum=0)  # not verified over IPv4
            pkt /= VXLAN(vni=VNI, flags=0x08)
            pkt /= inner_frame(
                REMOTE_HOST_MAC, LOCAL_HOST_MAC, REMOTE_HOST_IP, LOCAL_HOST_IP
            )
            vm = sport_vm()
        else:
            # Sent plain on the access port; grout encapsulates it.
            pkt = inner_frame(
                LOCAL_HOST_MAC, REMOTE_HOST_MAC, LOCAL_HOST_IP, REMOTE_HOST_IP
            )
            vm = sport_vm()

        return [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())]


def register():
    return Profile()
