# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: IPv4 + IPv6 dual-stack forwarding
#
# Two 64-byte streams per direction, one IPv4 and one IPv6, at equal rate.
# Each stream sweeps its UDP source port to spread the traffic over many flows.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

HOST4_P0 = "16.0.0.1"
HOST4_P1 = "48.0.0.1"
HOST6_P0 = "fd00:100::1"
HOST6_P1 = "fd00:200::1"

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
            ip4 = IP(src=HOST4_P0, dst=HOST4_P1)
            ip6 = IPv6(src=HOST6_P0, dst=HOST6_P1)
        else:
            eth = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            ip4 = IP(src=HOST4_P1, dst=HOST4_P0)
            ip6 = IPv6(src=HOST6_P1, dst=HOST6_P0)

        streams = []
        for ip in (ip4, ip6):
            pkt = eth / ip / UDP(sport=1024, dport=1024, chksum=0)
            pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"
            # Equal share of the offered rate between the two streams.
            streams.append(
                STLStream(
                    packet=STLPktBuilder(pkt=pkt, vm=sport_vm()),
                    mode=STLTXCont(percentage=50),
                )
            )

        return streams


def register():
    return Profile()
