#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

#
# Test SRv6 END.X behavior with FRR ISIS integration
# ISIS automatically generates END.X adjacency SIDs for links
#
# network layout:
#  grout (ISIS + SRv6)                    isis-peer (ISIS + SRv6)
#       p0                                        x-p0
#  2001:db8:1::1/64 <------ ISIS adjacency ------> 2001:db8:1::2/64
#                       (END.X SID auto-generated)
#
# IPv6 address plan:
# - 2001:db8:1::/64    - ISIS link network (documentation range)
# - 5f00:100::/48      - grout SRv6 locator (SRv6 reserved range)
# - 5f00:200::/48      - peer SRv6 locator (SRv6 reserved range)
#
# Test validates:
# - ISIS automatically generates END.X adjacency SIDs
# - grout receives END.X nexthops from FRR/zebra
# - END.X forces traffic via specific link (traffic engineering)
#

set -e
zebra=$(PATH="$1/frr_install/sbin:$1/frr_install/bin:$PATH" command -v zebra)
frr_version=$($zebra --version | sed -En 's/zebra version //p')
min_version=$(printf '%s\n%s\n' "$frr_version" "10.6.0" | sort -V | head -n1)
if ! [ "$min_version" = "10.6.0" ]; then
       echo "$0: FRR $frr_version does not support end.x"
       exit 125
fi

. $(dirname $0)/_init_frr.sh

# Create interface for ISIS link
create_interface p0
set_ip_address p0 2001:db8:1::1/64

# Configure grout with SRv6 locator and ISIS
vtysh <<-EOF
configure terminal
!
ipv6 router-id 2001:db8:1::1
!
segment-routing
 srv6
  locators
   locator loc_grout
    prefix 5f00:100::/48 block-len 32 node-len 16 func-bits 16
    behavior usid
   exit
  exit
 exit
exit
!
interface p0
 ipv6 router isis grout-srv6
 isis network point-to-point
exit
!
router isis grout-srv6
 net 49.0000.0000.0001.00
 is-type level-1
 topology ipv6-unicast
 segment-routing srv6
  locator loc_grout
 exit
exit
!
end
copy running-config startup-config
EOF

vtysh -c "show running-config" | grep -A20 "segment-routing\|router isis"

# Save grout FRR log path
grout_frr_log="$frr_log"

# Start ISIS peer in separate namespace
start_frr isis-peer 0
ip link set x-p0 netns isis-peer
ip -n isis-peer link set x-p0 up
ip -n isis-peer addr add 2001:db8:1::2/64 dev x-p0

mark_events

# Configure ISIS peer with SRv6
vtysh -N isis-peer <<-EOF
configure terminal
!
ipv6 router-id 2001:db8:1::2
!
segment-routing
 srv6
  locators
   locator loc_peer
    prefix 5f00:200::/48 block-len 32 node-len 16 func-bits 16
    behavior usid
   exit
  exit
 exit
exit
!
interface x-p0
 ipv6 address 2001:db8:1::2/64
 ipv6 router isis grout-srv6
 isis network point-to-point
exit
!
router isis grout-srv6
 net 49.0000.0000.0002.00
 is-type level-1
 topology ipv6-unicast
 segment-routing srv6
  locator loc_peer
 exit
exit
!
end
EOF

wait_event -t 30 'route6 add: vrf=main 5f00:100:0:1::/64 origin=isis' &&
nh_id=$(route_nh_id 5f00:100:0:1::/64 main SRv6-local) &&
assert_nexthop "$nh_id" '.behavior == "end.x"' || {
	vtysh -c "show isis neighbor detail"
	vtysh -c "show segment-routing srv6 locator"
	grcli route
	fail "No SRv6-local END.X nexthops found - ISIS SRv6 integration failed"
}

# behavior usid on the locator makes this a uA, not a plain End.X. The
# shift parameters come from the locator block and node lengths.
assert_nexthop "$nh_id" '.flavor | contains(["next-csid"])'
assert_nexthop "$nh_id" '.block_bits == 32 and .csid_bits == 16'

# The locator uses uSID, so the adjacency SID is a uA: grout consumes the
# active CSID and hands the packet to the peer over the adjacency instead
# of looking the result up. 5f00:100:0:1:: shifts to 5f00:100:1::, which
# no route covers, so the packet only comes back out if the L3 nexthop is
# really used.
ip -n isis-peer -6 route add 5f00:100::/48 via 2001:db8:1::1 dev x-p0

# Start the capture before the traffic. ping6 -i0.2 -c5 is done emitting after
# 0.8s, which tcpdump may not beat to opening its capture.
capture=$(mktemp)
ip netns exec isis-peer timeout 5 tcpdump -c1 -pnnli x-p0 ip6 dst 5f00:100:1:: >"$capture" 2>&1 &
tcpdump_pid=$!
for _ in $(seq 50); do
	if grep -q "listening on" "$capture"; then
		break
	fi
	sleep 0.1
done

ip netns exec isis-peer ping6 -i0.2 -c5 -n 5f00:100:0:1:: >/dev/null 2>&1 &
ping_pid=$!

if ! wait $tcpdump_pid; then
	cat "$capture"
	rm -f "$capture"
	wait $ping_pid
	grcli trace show count 20
	fail "END.X did not forward the packet to the adjacency"
fi
rm -f "$capture"
wait $ping_pid || true
