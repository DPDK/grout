#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

# This test verifies VPNv4 route exchange using BGP over IPv6 (BGP6) with SRv6 between
# FRR+Grout and a standalone FRR BGP peer. Each router advertises its local IPv4 subnet
# via VPNv4, assigns SRv6 SIDs, and imports the remote route into its VRF.
#
# Success criteria:
#   - FRR+Grout learns 16.0.0.0/24 from the BGP peer.
#   - The BGP peer learns 16.1.0.0/24 from FRR+Grout.
#   - Host-A and Host-B can ping each other through the SRv6/VPNv4 BGP6 exchange.
#
#
# +---------------------------------+    +-----------------------------------+
# |                                 |    |                                   |
# |           frr-bgp-peer          |    |           FRR + Grout             |
# |                                 |    |                                   |
# |                                 |    |                                   |
# |      vrf 1                      |    |                       gr-vrf1     |
# | +------------+  +-------------+ |    | +-------------+   +-------------+ |
# | | to-host-a  |  |   x-p0      | |    | |     p0      |   |     p1      | |
# +-+            +--+             +-+    +-+             +---+             +-+
#   |  16.0.0.1  |  | fd00:102::1 |        | fd00:102::2 |   |   16.1.0.1  |
#   +-----+------+  +----------+--+        +---+---------+   +-------------+
#         |                    |               |                   |
#         |                    |               |                   |
#         |                    |   srv6/vpn4   |                   |
#    +----+-----+              +---------------+              +----+-----+
#    |   eth0   |                                             |   x-p1   |
#  +-|          +-+                                         +-|          +-+
#  | | 16.0.0.2 | |                                         | | 16.1.0.2 | |
#  | +----------+ |        <-----      PING    ----->       | +----------+ |
#  |    Host-A    |                                         |    Host-B    |
#  +--------------+                                         +--------------+
#

. $(dirname $0)/_init_frr.sh

create_vrf gr-vrf1

create_interface p0
create_interface p1 vrf gr-vrf1

set_ip_address p0 fd00:102::2/64
set_ip_address p1 16.1.0.1/24
set_ip_route 2001:db8::/32 fd00:102::1

netns_add ns-a
netns_add ns-b

# Configure Host-B
move_to_netns x-p1 ns-b
ip -n ns-b addr add 16.1.0.2/24 dev x-p1
ip -n ns-b route add default via 16.1.0.1
ip -n ns-b addr show

# Create and start an FRR instance for the BGP peer
start_frr bgp-peer 0
ip link set x-p0 netns bgp-peer
ip netns exec bgp-peer sysctl -w net.vrf.strict_mode=1
ip netns exec bgp-peer sysctl -w net.ipv6.conf.all.seg6_enabled=1
ip netns exec bgp-peer sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec bgp-peer sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec bgp-peer sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec bgp-peer sysctl -w net.ipv4.conf.default.rp_filter=0

ip -n ns-a link add eth0 type veth peer name to-host-a
ip -n ns-a link set to-host-a up
ip -n ns-a link set eth0 up

# Configure Host-A
ip -n ns-a addr add 16.0.0.2/24 dev eth0
ip -n ns-a route
ip -n ns-a addr show
ip -n ns-a route add default via 16.0.0.1

# Configure FRR BGP peer router
ip -n ns-a link set to-host-a netns bgp-peer
ip -n bgp-peer link add vrf1 type vrf table 1000
ip -n bgp-peer link set vrf1 up

ip -n bgp-peer link set to-host-a master vrf1

vtysh -N bgp-peer <<-EOF
configure terminal

interface vrf1
 vrf vrf1
exit

interface x-p0
 ip address fd00:102::1/64
exit

interface to-host-a
  ip address 16.0.0.1/24
exit

ipv6 route 2001:db8::/32 fd00:102::2

segment-routing
 srv6
  locators
   locator loc1
    prefix 2001:db8:1:1::/64 func-bits 8
   exit
  exit
 exit

router bgp 64512
 bgp router-id 172.16.0.2

 neighbor fd00:102::2 remote-as 64512
 neighbor fd00:102::2 capability extended-nexthop

 address-family ipv4 vpn
  neighbor fd00:102::2 activate
 exit-address-family

 segment-routing srv6
  locator loc1
 exit
exit

router bgp 64512 vrf vrf1
 bgp router-id 176.16.0.201
 no bgp default ipv4-unicast

 address-family ipv4 unicast
  rd vpn export 64512:1
  rt vpn both 64512:1
  label vpn export auto
  export vpn
  import vpn
  redistribute connected
  sid vpn export auto
 exit-address-family
exit

EOF

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal

segment-routing
 srv6
  locators
   locator loc1
    prefix 2001:db8:2:2::/64 func-bits 8
   exit
  exit
 exit

router bgp 64512
 bgp router-id 172.16.0.1

 neighbor fd00:102::1 remote-as 64512
 neighbor fd00:102::1 capability extended-nexthop
 neighbor fd00:102::1 update-source fd00:102::2

 address-family ipv4 vpn
  neighbor fd00:102::1 activate
 exit-address-family

 segment-routing srv6
  locator loc1
 exit
exit

router bgp 64512 vrf gr-vrf1
 bgp router-id 172.16.0.101
 no bgp default ipv4-unicast

 address-family ipv4 unicast
  rd vpn export 64512:1
  rt vpn both 64512:1
  label vpn export auto
  export vpn
  import vpn
  redistribute connected
  sid vpn export auto
 exit-address-family
exit

EOF

# Wait for BGP routes to be exchanged
attempts=0
while ! grcli route show | grep -qE '16.0.0.0/24[[:space:]]+\<bgp\>[[:space:]]+\<type=SRv6\>'; do
	if [ "$attempts" -ge 40 ]; then
		fail "BGP SRv6 route not learned in Grout"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

attempts=0
while ! grcli route show | grep -qE '2001:db8:2:2:100::/128[[:space:]]+\<bgp\>[[:space:]]+\<type=SRv6-local\>'; do
	if [ "$attempts" -ge 40 ]; then
		fail "BGP SRv6-local route not learned in Grout"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

attempts=0
while ! vtysh -N bgp-peer -c "show ip route vrf vrf1" | grep -q "B>\* 16.1.0.0/24 .*seg6" ; do
	if [ "$attempts" -ge 40 ]; then
		fail "BGP seg6 route not learned in FRR BGP Peer"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

attempts=0
while ! vtysh -N bgp-peer -c "show ipv6 route" | grep -q "B>\* 2001:db8:1:1:100::/128 .*seg6local" ; do
	if [ "$attempts" -ge 40 ]; then
		fail "BGP seg6local route not learned in FRR BGP Peer"
	fi
	sleep 0.5
	attempts=$((attempts + 1))
done

# Verify host-a can ping host-b
ip netns exec ns-a ping -i0.01 -c3 -n 16.1.0.2
ip netns exec ns-b ping -i0.01 -c3 -n 16.0.0.2
