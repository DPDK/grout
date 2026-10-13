#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Andrea Panattoni

# Two ports reserve all 1024 mbufs in one pool; punted UDP must not starve RX.
grout_port_queue_size=128
trace_enable=false
. "$(dirname "$0")/_init.sh"

port_add p0
grcli address add 10.0.0.1/24 iface p0
netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 10.0.0.2/24 dev x-p0

port_add p1
grcli address add 10.0.1.1/24 iface p1
netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 10.0.1.2/24 dev x-p1

cat > $tmp/udpflow.py <<'EOF'
import socket, sys, time

data = b"x" * 20
dest = (sys.argv[1], 9)

try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            s.sendto(data, dest)
except KeyboardInterrupt:
    pass
EOF

ip netns exec n0 python3 $tmp/udpflow.py 10.0.0.1 &
pid=$!
echo "kill -INT $pid" >> $tmp/cleanup
ip netns exec n1 python3 $tmp/udpflow.py 10.0.1.1 &
pid=$!
echo "kill -INT $pid" >> $tmp/cleanup

SECONDS=0
while [ "$SECONDS" -lt 5 ]; do
	sleep 1
	if grcli stats show hardware pattern '*.rx_mbuf_allocation_errors' | grep .; then
		fail "ran out of RX mbufs at ${SECONDS}s"
	fi
done
