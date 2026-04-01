#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

# Verify ARP/ND suppression with manually configured remote nexthops.
#
# A bridge with neigh_suppress has two ports. A remote nexthop (with a known
# MAC) is installed for a target IP. When a host sends an ARP request for that
# IP, grout replies locally using the remote nexthop's MAC instead of flooding
# the request to the other port.
#
#   .-------------.      .---------------------------.      .-------------.
#   |    host-a   |      |           grout           |      |    host-b   |
#   |             |      |                           |      |             |
#   |  10.0.0.2   |      |          10.0.0.1         |      |  10.0.0.3   |
#   |  +-------+  |      | +----+   +------+  +----+ |      |  +-------+  |
#   |  | x-p0  + - - - - - + p0 +---+ br0  +--+ p1 + - - - - - + x-p1  |  |
#   |  +-------+  |      | +----+   +------+  +----+ |      |  +-------+  |
#   |             |      |    remote nh: 10.0.0.99   |      |             |
#   |             |      |   mac ba:d0:ca:ca:99:99   |      |             |
#   '-------------'      '---------------------------'      '-------------'

. $(dirname $0)/_init.sh

grcli interface add bridge br0 neigh_suppress on neigh_snoop on
grcli address add 10.0.0.1/24 iface br0

port_add p0 domain br0
port_add p1 domain br0

netns_add host-a
move_to_netns x-p0 host-a
ip -n host-a addr add 10.0.0.2/24 dev x-p0

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 10.0.0.3/24 dev x-p1

# Verify normal L2 connectivity works (non-suppressed traffic).
ip netns exec host-a ping -i0.01 -c3 -W1 -n 10.0.0.3 || fail "L2 ping host-a->host-b failed"
ip netns exec host-b ping -i0.01 -c3 -W1 -n 10.0.0.2 || fail "L2 ping host-b->host-a failed"

# Install a remote nexthop for the suppressed IP.
grcli nexthop add l3 iface br0 address 10.0.0.99 mac ba:d0:ca:ca:99:99 remote

# Send an ARP request from host-a for the suppressed IP.
ip netns exec host-a arping -b -c2 -w3 -I x-p0 10.0.0.99 | tee $tmp/arping.out &
arping_pid=$!

# Capture on host-b filtering only for ARP targeting 10.0.0.99.
ip netns exec host-b timeout 3 \
	tcpdump -c1 -tlpnn -i x-p1 'arp and arp[24:4] = 0x0a000063' 2>&1 &&
	fail "ARP request for 10.0.0.99 was flooded to host-b (should have been suppressed)"

# Wait for arping to finish.
wait $arping_pid

# Verify the suppressed ARP reply has the correct remote MAC.
if ! grep -qi 'ba:d0:ca:ca:99:99' $tmp/arping.out; then
	cat $tmp/arping.out
	fail "ARP reply did not contain expected MAC ba:d0:ca:ca:99:99"
fi
