#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet


action=${1:-unset}

if [ $action == "build" ]; then
    # run by "make smoke-tests"
    action=run
    . $(dirname $0)/_init.sh

else
    # run from command line
    fail() { exit 1; }
    export PATH=$PATH:$(dirname $0)/../build
    run_id=p
    set -x
fi


cli_add_del_test() {
    grcli add sr steer 0.0.0.0/0 next 1::2 1::3 1::4 1::5
    grcli add sr steer 10.0.0.0/16 next fe80::d0ad:caff:fefe:b412 fe80::d0ad:caff:fefe:b413
    grcli add sr steer 10.0.0.0/16 next fe80::d0ad:caff:fefe:b412 && fail "existing dest"
    grcli add sr steer 10.0.0.0/16 next fe80::d0ad:caff:fefe:b412 vrf 10
    grcli add sr steer 100::1/64 next fe80::d0ad:caff:fefe:b412 fe80::d0ad:caff:fefe:b413 fe80::d0ad:caff:fefe:b414
    grcli add sr steer 200::1/64 next fe80::d0ad:caff:fefe:b412 fe80::d0ad:caff:fefe:b413 fe80::d0ad:caff:fefe:b414 1::2
    grcli add sr steer 300::1/64 next fe80::d0ad:caff:fefe:b412 fe80::d0ad:caff:fefe:b413 fe80::d0ad:caff:fefe:b414 1::2 1::3 1::4
    grcli show sr steer
    grcli del sr steer 0.0.0.0/0
    grcli del sr steer 200::1/64
    grcli del sr steer 10.0.0.0/16
    grcli del sr steer 10.0.0.0/16 && fail "no entry"
    grcli del sr steer 10.0.0.0/16 vrf 10
    grcli show sr steer

    grcli add sr localsid 1::2 behavior end.dt4
    grcli add sr localsid 2::2 behavior end.dt4 table 25
    grcli add sr localsid 3::2 behavior end
    grcli add sr localsid 3::2 behavior end vrf 50
    grcli add sr localsid fe80::d0ad:caff:fefe:b412 behavior end.t table 100 vrf 50
    grcli show sr localsid
    grcli del sr localsid 3::2
    grcli del sr localsid 3::2 && fail "no entry"
    grcli del sr localsid 3::2 vrf 50
    grcli show sr localsid
}

run_in_lab() {

    p0=${run_id}0
    p1=${run_id}1

    ip netns del $p0 2> /dev/null || true
    ip netns del $p1 2> /dev/null || true
    ip netns add $p0
    ip netns add $p1

    # setup ports and connected
    grcli add interface port $p0 devargs net_tap0,iface=$p0 mac d2:f0:0c:ba:a5:10
    grcli add interface port $p1 devargs net_tap1,iface=$p1 mac d2:f0:0c:ba:a5:11
    grcli add ip6 address fd00:101::1/64 iface $p0
    grcli add ip6 address fd00:102::1/64 iface $p1
    grcli add ip address 192.168.61.1/24 iface $p0
    grcli add ip address 192.168.62.1/24 iface $p1
    ip link set $p0 netns $p0
    ip -n $p0 link set $p0 address d2:ad:ca:fe:b4:10
    ip -n $p0 link set lo up
    ip -n $p0 link set $p0 up
    ip -n $p0 addr add fd00:101::2/64 dev $p0
    ip -n $p0 addr add 192.168.61.2/24 dev $p0
    ip link set $p1 netns $p1
    ip -n $p1 link set $p1 address d2:ad:ca:fe:b4:11
    ip -n $p1 link set lo up
    ip -n $p1 link set $p1 up
    ip -n $p1 addr add fd00:102::2/64 dev $p1
    ip -n $p1 addr add 192.168.62.2/24 dev $p1

    sleep 3


    #
    # network layout:
    #  (client) p0(netns) <--> p0 <grout> p1 <--->  p1(netns) (public: 192.168.60.1/24 on p0)
    #       ipv4 ---------------|        srv6        |-- ipv4
    #
    # test case:
    #   - (1) send ipv4 ping from p0
    #   - (2) grout encap in srv6, send to sid fd00:202::2
    #   - (3) linux p1 decap it
    #   - (4) reply to ping
    #   - (5) linux p1 reencap in srv6, send to grout sid fd00:202::100,
    #   - (6) grout decap it, reply back in ipv4 to p0
    #

    # only linux's p1 will see srv6
    ip netns exec $p1 sysctl -w net.ipv6.conf.$p1.seg6_enabled=1
    ip netns exec $p1 sysctl -w net.ipv6.conf.$p1.forwarding=1

    # (1) send ipv4 to grout
    ip -n $p0 route add default via 192.168.61.1 dev $p0

    # (2)
    grcli add sr steer 192.168.0.0/16 next fd00:202::2
    grcli add ip6 route fd00:202::/64 via fd00:102::2

    # (3)
    ip -n $p1 -6 route add fd00:202::2 encap seg6local action End.DX4 nh4 192.168.60.1 count dev $p1

    # (4) 192.168.60.0/24 is our 'public' network
    ip -n $p1 addr add 192.168.60.1/24 dev $p1

    # (5)
    ip -n $p1 route add 192.168.61.0/24 encap seg6 mode encap segs fd00:202::100 dev $p1
    ip -n $p1 -6 route add fd00:202::/64 via fd00:102::1 dev $p1

    # (6)
    grcli add sr localsid fd00:202::100 behavior end.dt4

    # test
    ip netns exec $p0 ping -c 3 192.168.60.1
}


case $action in
    cli) cli_add_del_test ;;
    run) run_in_lab ;;
    *) fail "action '$action' not recognized" ;;
esac
