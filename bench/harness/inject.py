#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

"""
Inject a bench *.py traffic profile through a live grout and check forwarding.

The profile is loaded against the mock trex_stl_lib shipped next to this file,
so no real TRex is needed. For each direction the profile's base packet(s) are
sent on the ingress tap while the egress tap is sniffed; the direction passes
if at least one frame is forwarded out. Direction 0 is p0 -> p1, direction 1 is
p1 -> p0 (see bench/README.md).
"""

import argparse
import importlib.machinery
import importlib.util
import os
import sys
import threading
import time

from scapy.config import conf
from scapy.sendrecv import AsyncSniffer, sendp


def load_profile(path):
    here = os.path.dirname(os.path.abspath(__file__))
    # Make "import trex_stl_lib.api" resolve to the mock shipped next to this file.
    sys.path.insert(0, here)
    loader = importlib.machinery.SourceFileLoader("traffic_profile", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod.register()


def direction_packets(profile, direction):
    return [stream.packet.pkt for stream in profile.get_streams(direction=direction)]


def run_direction(profile, direction, ingress, egress, count):
    pkts = direction_packets(profile, direction)

    started = threading.Event()
    sniffer = AsyncSniffer(iface=egress, store=True, started_callback=started.set)
    sniffer.start()
    started.wait(2)

    sendp(pkts * count, iface=ingress, verbose=False)
    time.sleep(0.5)  # let grout forward

    sniffer.stop()
    got = sniffer.results or []
    sent = len(pkts) * count
    ok = len(got) >= sent

    print(f"dir{direction} {ingress} -> {egress}: [{'PASS' if ok else 'FAIL'}]")
    print(f"    sent {ingress}: {sent} packets")
    for p in pkts * count:
        print(f"        {p.summary()}")
    print(f"    received {egress}: {len(got)} packets")
    for g in got:
        print(f"        {g.summary()}")

    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traffic", required=True, help="path to the *.py traffic profile")
    ap.add_argument("--p0", required=True, help="tap connected to grout p0")
    ap.add_argument("--p1", required=True, help="tap connected to grout p1")
    ap.add_argument("--count", type=int, default=3, help="repeats per stream")
    args = ap.parse_args()

    conf.verb = 0

    profile = load_profile(args.traffic)
    ok = True
    ok = run_direction(profile, 0, args.p0, args.p1, args.count) and ok
    ok = run_direction(profile, 1, args.p1, args.p0, args.count) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
