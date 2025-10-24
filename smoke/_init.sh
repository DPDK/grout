# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e -o pipefail

: "${test_frr:=false}"

if [ -n "$ZEBRA_DEBUG_DPLANE_GROUT" ]; then
	run_frr=false
else
	run_frr=true
fi

if [ -S "$GROUT_SOCK_PATH" ]; then
	run_grout=false
else
	run_grout=true
fi

: "${use_hardware_ports:=false}"
# Usage example
# export NET_INTERFACES="eno12399v1 eno12409v1"
# export VFIO_PCI_PORTS="0000:8a:01.0 0000:8a:11.0"
if [ -n "$NET_INTERFACES" ] && [ -n "$VFIO_PCI_PORTS" ]; then
	net_interfaces=($NET_INTERFACES)
        vfio_pci_ports=($VFIO_PCI_PORTS)
        if [ "${#net_interfaces[@]}" -ne "${#vfio_pci_ports[@]}" ]; then
		echo "error: NET_INTERFACES and VFIO_PCI_PORTS must have equal length" >&2
                exit 1
	fi
	use_hardware_ports=true
fi

cleanup() {
	status="$?"
	set +e
	sh -x $tmp/cleanup
	# delete all non-port interfaces first
	grcli interface show |
	grep -Ev -e ^NAME -e '\<port[[:space:]]+devargs=' -e '\<loopback\>' |
	while read -r name _; do
		grcli interface del "$name"
	done
	# then delete all ports
	grcli interface show |
	grep -ve ^NAME -e '\<loopback\>' |
	while read -r name _; do
		grcli interface del "$name"
	done
	[ -s $tmp/restore_interfaces ] && sh -x $tmp/restore_interfaces

	kill %?grcli
	wait %?grcli

	if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
		frrinit.sh stop
		kill %?tail
		wait %?tail

		# should be already stopped
		for daemon in watchfrr.sh zebra staticd mgmtd vtysh; do
			pids=$(pgrep -f "$builddir/frr_install/.*/$daemon")
			if [ -n "$pids" ]; then
				echo "$pids" | xargs -r kill -9
			fi
		done
	fi
	if [ "$run_grout" = true ]; then
		set +x
		kill -15 "$grout_pid"
		wait "$grout_pid"
		ret="$?"
		if [ "$ret" -ne 0 ]; then
			status="$ret"
			if [ "$ret" -gt 128 ]; then
				sig=$((ret - 128))
				echo "fail: grout terminated by signal SIG$(kill -l $sig)"
			else
				echo "fail: grout exited with an error status $ret"
			fi >&2
			if [ -n "$core_pattern" ]; then
				# core dumps written to files
				for core in $tmp/core.*.*; do
					[ -f "$core" ] || continue
					gdb -c "$core" -batch \
						-ex "info threads" \
						-ex "thread apply all bt"
				done
				 # restore original core pattern
				sysctl -w kernel.core_pattern="$core_pattern"
			else
				# fallback to systemd-coredump, if available
				coredumpctl info --no-pager "$grout_pid"
			fi
		fi
		set -x
	fi
	rm -rf -- "$tmp"
	exit $status
}

fail() {
	echo "fail: $*" >&2
	return 1
}

tmp=$(mktemp -d)
trap cleanup EXIT
builddir=${1-}

netns_add() {
	local ns="$1"
	ip netns add "$ns"
	cat >> $tmp/cleanup <<EOF
ip netns pids "$ns" | xargs -r kill --timeout 500 KILL
ip netns del "$ns"
EOF
	ip -n "$ns" link set lo up
}

tap_counter=0
port_add() {
	local name="$1"
	shift
        if [ "$use_hardware_ports" = true ]; then
		ip link set "${net_interfaces[$tap_counter]}" name "x-$name"
		# When a namespace is deleted while a renamed kernel interface
		# is inside it an 'altname' property with the interface original
		# name is created. This causes an error on attempt to restore
		# the original name. So we need to clear this 'altname' first.
		echo "ip link property del dev x-$name altname ${net_interfaces[$tap_counter]} || :" >> $tmp/restore_interfaces
		echo "ip link set x-$name name ${net_interfaces[$tap_counter]}" >> $tmp/restore_interfaces
		grcli interface add port "$name" devargs "${vfio_pci_ports[$tap_counter]}" "$@"
	else
		grcli interface add port "$name" devargs "net_tap$tap_counter,iface=x-$name" "$@"
		# Ensure the Linux net device has a different mac address from
		# grout's. This is required to avoid Linux from wrongfully
		# assuming the packets sent by grout originated locally.
		local mac=$(echo "$name" | md5sum | sed -E 's/(..)(..)(..)(..)(..).*/02:\1:\2:\3:\4:\5/')
		ip link set "x-$name" address "$mac"
	fi
	tap_counter=$((tap_counter + 1))
}

llocal_addr() {
	grcli address show iface "$1" | sed -En "s/^$1[[:space:]]+(fe80:.+)\\/64\$/\\1/p"
}

if [ "$run_grout" = true ]; then
	export GROUT_SOCK_PATH=$tmp/grout.sock
fi
if [ -n "${builddir}" ]; then
	export PATH=$builddir:$PATH
fi

grout_extra_options=""
if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	chmod 0755 $tmp # to access on tmp
	grout_extra_options+="-m 0666"
	export ZEBRA_DEBUG_DPLANE_GROUT=1
	if [ -n "${builddir}" ]; then
		export PATH=$builddir/frr_install/sbin:$builddir/frr_install/bin:$PATH
	fi
fi

cat >> $tmp/cleanup <<EOF
echo ================== CLEANUP ==================
grcli stats show software
grcli trace show count 50
EOF

if [ -t 1 ]; then
	# print bash xtrace in cyan
	exec 9> >(awk '{print "\033[36m" $0 "\033[0m"}')
	export BASH_XTRACEFD=9
	export PS4='+ '
fi

set -x

if [ "$run_grout" = true ]; then
	ulimit -c unlimited
	core_pattern=$(sysctl -n kernel.core_pattern)
	if ! sysctl -w kernel.core_pattern="$tmp/core.%e.%p"; then
		unset core_pattern
	fi
	export ASAN_OPTIONS=disable_coredump=0
	if [ "$use_hardware_ports" = false ]; then
		grout_extra_options+=" -t"
	fi
	if [ -t 1 ]; then
		# print grout logs in blue (stderr in bold red)
		taskset -c 0,1 grout -vvx $grout_extra_options \
			> >(awk '{print "\033[34m" $0 "\033[0m"}') \
			2> >(awk '{print "\033[1;31m" $0 "\033[0m"}' >&2) &
	else
		taskset -c 0,1 grout -vvx $grout_extra_options &
	fi
fi
socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH,retry=10
if [ "$run_grout" = true ]; then
	grout_pid=$(pgrep -g0 grout)
fi

case "$(basename $0)" in
config_test.sh|graph_svg_test.sh)
	;;
*)
	grcli trace enable all
	;;
esac

if [ -t 1 ]; then
	# print events in yellow
	grcli events | awk '{print "\033[33m" $0 "\033[0m"}' &
else
	grcli events &
fi

if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	zlog="$builddir/frr_install/var/log/frr/zebra.log"
	rm -f "$zlog"
	touch "$zlog"
	if [ -t 1 ]; then
		# zebra logs in magenta
		tail -f "$zlog" | awk '{print "\033[35m" $0 "\033[0m"}' &
	else
		tail -f "$zlog" &
	fi
	frrinit.sh start
	attempts=25

	# wait that zebra_dplane_grout get iface event from grout
	while ! grep -q "GROUT:.*iface/ip events" "$zlog" 2>/dev/null; do
		if [ "$attempts" -le 0 ]; then
			fail "Zebra is not listening grout events."
		fi
		sleep 0.2
		attempts=$((attempts - 1))
	done
fi
