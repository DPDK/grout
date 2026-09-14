# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: IPv4 forwarding
#
# 64-byte IPv4/UDP frames, 16.0.0.0/16 <-> 48.0.0.0/16. An STLVM sweeps the UDP
# source port to spread the traffic over many flows.

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

HOST_P0 = "16.0.0.1"
HOST_P1 = "48.0.0.1"

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
            ip = IP(src=HOST_P0, dst=HOST_P1)
        else:
            eth = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            ip = IP(src=HOST_P1, dst=HOST_P0)

        pkt = eth / ip / UDP(sport=1024, dport=1024, chksum=0)
        pkt /= max(0, FRAME_SIZE - len(pkt)) * b"x"

        return [
            STLStream(packet=STLPktBuilder(pkt=pkt, vm=sport_vm()), mode=STLTXCont())
        ]


def register():
    return Profile()
