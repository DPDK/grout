# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: VXLAN L3VPN, IPv6 underlay
#
# Same asymmetric L3VPN profile as vxlan_l3vpn_ipv4 but with an IPv6 underlay
# (outer IPv6 header). The overlay and customer traffic stay IPv4.
#
#   direction 0 (TRex port 0 -> grout p0): VXLAN frame whose inner Ethernet is
#     addressed to grout's local RMAC; grout decaps, routes the inner IPv4
#     packet toward the customer subnet and sends it plain out p1;
#
#   direction 1 (TRex port 1 -> grout p1): plain IPv4 packet toward the overlay
#     subnet; grout routes it to the remote next hop and VXLAN-encaps it out p0.
#
# Flow spreading (both are source UDP ports, one per emulated client):
#   - decap direction: the outer VXLAN UDP source port is swept (the RSS key on
#     grout's receive side). Over an IPv6 underlay grout verifies the outer UDP
#     checksum, so the field engine recomputes it in lockstep with the swept port:
#     each +1 on the source port cancels a -1 on the one's-complement checksum.
#     Hardware checksum offload is deliberately avoided: on real NICs it corrupts
#     the inner IPv4 header checksum of the tunneled frame;
#   - encap direction: the customer UDP source port is swept; grout derives the
#     outer VXLAN source port from the inner flow hash, so this spreads the
#     encapsulated traffic on the wire.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

# Underlay VTEP addresses.
LOCAL_VTEP = "fd00:0::1"
REMOTE_VTEP = "fd00:0::2"
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


def decap_sweep_vm(pkt):
    # Sweep the outer UDP source port to spread decap traffic across grout's RX
    # queues, keeping the outer UDP checksum valid without hardware offload (which
    # corrupts the inner IPv4 checksum on real NICs). Incrementing the source port
    # by one decrements the one's-complement checksum by one, so a lockstep dec
    # var keeps every packet valid. The sweep stops before the checksum reaches
    # zero to avoid the end-around carry wrap.
    base = Ether(bytes(pkt))[UDP].chksum
    span = base - 1
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=1024 + span, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    vm.var(name="ocks", min_value=base - span, max_value=base, size=2, op="dec")
    vm.write(fv_name="ocks", pkt_offset="UDP:0.chksum")
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
            pkt /= IPv6(src=REMOTE_VTEP, dst=LOCAL_VTEP)
            pkt /= UDP(sport=1024, dport=4789)  # swept, checksum kept valid by VM
            pkt /= VXLAN(vni=VNI, flags=0x08)
            pkt /= routed_frame(
                Ether(src=REMOTE_RMAC, dst=LOCAL_RMAC), OVERLAY_HOST, CUSTOMER_HOST
            )
            vm = decap_sweep_vm(pkt)
        else:
            # Plain routed packet toward the overlay subnet.
            pkt = routed_frame(
                Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC), CUSTOMER_HOST, OVERLAY_HOST
            )
            vm = sport_vm()

        return [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())]


def register():
    return Profile()
