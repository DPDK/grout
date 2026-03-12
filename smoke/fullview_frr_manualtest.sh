#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

if [ -z "$1" ] ; then echo "Build dir not specified" ; exit 1; fi

if ! command -v gobgpd &> /dev/null && ! command -v $1/gobgpd ; then
	BASE=https://github.com/osrg/gobgp/releases/download/
	VERSION=4.3.0
	case $(uname -m) in
	x86_64)
	      ARCH=amd64
	      ;;
	aarch64)
	      ARCH=arm64
	      ;;
	*)
	      echo "error: gobgp not available on architecture $(uname -m)"
	      exit 1
	      ;;
	esac
	echo "gobgpd not found, downloading"
	curl -fsSL ${BASE}/v${VERSION}/gobgp_${VERSION}_linux_${ARCH}.tar.gz | tar -C "$1" -zxf -
fi

if [ ! -f "$1/latest-bview" ] ; then
	echo "bgp full view not found, downloading"
	curl -fsSL https://data.ris.ripe.net/rrc10/latest-bview.gz | gunzip > $1/latest-bview
fi

grout_verbose_level=0
grout_memory=4096
trace_enable=false
follow_events=false

. $(dirname $0)/_init_frr.sh

create_interface p0
netns_add bgp-peer
move_to_netns x-p0 bgp-peer
ip -n bgp-peer addr add 172.16.0.2/24 dev x-p0


set_ip_address p0 172.16.0.1/24
set_ip_route 0.0.0.0/0 172.16.0.2

grcli route config set vrf main  rib4-routes 1000000

# Configure Grout FRR instance
vtysh <<-EOF
configure terminal
ipv6 forwarding
no debug zebra dplane dpdk

route-map allow-all permit 1
exit
route-map deny-all deny 1
exit

router bgp 65002
	bgp router-id 172.16.0.1
	no bgp reject-as-sets
	no bgp ebgp-requires-policy
	neighbor 172.16.0.2 remote-as 65001
	neighbor 172.16.0.2 route-map allow-all in
	neighbor 172.16.0.2 route-map deny-all out
exit
EOF

cat >$1/gobgpd.conf <<-EOF
[global.config]
	as = 65001
	router-id = "172.16.0.2"
[[neighbors]]
	[neighbors.config]
	neighbor-address = "172.16.0.1"
	peer-as = 65002
[[policy-definitions]]
  name = "policy1"
  [[policy-definitions.statements]]
    name = "statement1"
    [policy-definitions.statements.actions.bgp-actions]
      set-next-hop = "172.16.0.2"
[global.apply-policy.config]
  export-policy-list = ["policy1"]
  # default-import-policy = "accept-route"
  default-export-policy = "accept-route"

EOF

ip netns exec bgp-peer gobgpd -f $1/gobgpd.conf &
sleep 3
time ip netns exec bgp-peer gobgp mrt inject global $1/latest-bview
vtysh <<-EOF
show ip bgp summary
EOF
# While the routes are injected to FRR, they may not be yet in grout
sleep 3
grcli route config show
