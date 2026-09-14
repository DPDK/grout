# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry
#
# name: IPv4 IMIX forwarding
#
# Standard Internet MIX: three IPv4/UDP streams per direction with sizes
# 60 / 590 / 1514 bytes weighted 28 / 16 / 4 (based on the TRex upstream imix.py
# example). Each stream sweeps its UDP source port so the load spreads over many
# flows (and thus over the receive queues).

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

HOST_P0 = "16.0.0.1"
HOST_P1 = "48.0.0.1"

IMIX_TABLE = [
    {"size": 60, "pps": 28, "isg": 0.0},
    {"size": 590, "pps": 16, "isg": 0.1},
    {"size": 1514, "pps": 4, "isg": 0.2},
]


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


class Profile:
    def create_stream(self, eth, src, dst, size, pps, isg):
        base = eth / IP(src=src, dst=dst) / UDP(sport=1024, dport=1024, chksum=0)
        pad = max(0, size - len(base)) * b"x"
        pkt = STLPktBuilder(pkt=base / pad, vm=sport_vm())
        return STLStream(isg=isg, packet=pkt, mode=STLTXCont(pps=pps))

    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            eth = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            src, dst = HOST_P0, HOST_P1
        else:
            eth = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            src, dst = HOST_P1, HOST_P0

        return [self.create_stream(eth, src, dst, **entry) for entry in IMIX_TABLE]


def register():
    return Profile()
