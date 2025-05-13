#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy

set -e

test_frr=true


ls -alt $builddir
ls -alt $builddir/frr_install
ls -alt $builddir/frr_install/share
ls -alt $builddir/frr_install/share/yang
ls -alt $builddir/frr_install/var
ls -alt $builddir/frr_install/var/run
ls -alt $builddir/frr_install/var/run/frr

. $(dirname $0)/_init.sh

ps -ef | grep zebra
ps -ef | grep staticd
ps -ef | grep mgmtd

p0=${run_id}0
p1=${run_id}1
# use veth pair because tap driver doesn't support ns
ip link add v0-$p0 type veth peer name v1-$p0
ip link add v0-$p1 type veth peer name v1-$p1

for n in 0 1; do
	p=$run_id$n
	netns_add n-$p
	ip link set v1-$p netns n-$p
	ip -n n-$p link set v1-$p address ba:d0:ca:ca:00:0$n
	ip -n n-$p link set v1-$p up
	ip -n n-$p link set lo up
	ip -n n-$p addr add 172.16.$n.2/24 dev v1-$p
	ip -n n-$p addr add 16.$n.0.1/16 dev lo
	ip -n n-$p route add default via 172.16.$n.1
	ip -n n-$p addr show
done

grcli add interface port $p0 devargs net_tap0,iface=tap-$p0,remote=v0-$p0 mac f0:0d:ac:dc:00:00
grcli add interface port $p1 devargs net_tap1,iface=tap-$p1,remote=v0-$p1 mac f0:0d:ac:dc:00:01

vtysh -c "configure terminal"           \
      -c "interface ${p0}"              \
      -c "ip address 172.16.0.1/24"     \
      -c "exit"                         \
      -c "interface ${p1}"              \
      -c "ip address 172.16.1.1/24"     \
      -c "exit"

vtysh -c "configure terminal" \
      -c "ip route 16.0.0.0/16 172.16.0.2" \
      -c "ip route 16.1.0.0/16 172.16.1.2" \
      -c "exit"

sleep 3 # wait zebra sync (TOFIX)

ip netns exec n-$p0 ping -i0.01 -c3 -n 16.1.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -n 16.0.0.1
ip netns exec n-$p0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n-$p1 ping -i0.01 -c3 -n 172.16.0.2
ip netns exec n-$p0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec n-$p1 ping -i0.01 -c3 -n 172.16.1.1
ip netns exec n-$p0 traceroute -N1 -n 16.1.0.1
ip netns exec n-$p1 traceroute -N1 -n 16.0.0.1
ip netns exec n-$p0 traceroute -N1 -n 172.16.1.2
ip netns exec n-$p1 traceroute -N1 -n 172.16.0.2
