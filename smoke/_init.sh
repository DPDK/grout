# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

set -e -o pipefail

ulimit -c unlimited

if [ "${_SMOKE_UNSHARED:-}" != 1 ]; then
	# pass the host netns as fd 3 so we can reference it after unshare
	export _SMOKE_UNSHARED=1
	exec unshare --mount --net -- "$0" "$@" 3</proc/1/ns/net
fi

if [ "${_SMOKE_MOUNTS_DONE:-}" != 1 ]; then
	# prevent any mount events from leaking to the host
	mount --make-rprivate /
	# start with a clean /run/netns, free of any stale host entries
	mkdir -p /run/netns
	mount -t tmpfs tmpfs /run/netns
	# register the host netns so hardware port tests can move devices in/out
	touch /run/netns/host
	mount --bind /proc/self/fd/3 /run/netns/host
	export _SMOKE_MOUNTS_DONE=1
fi

if [ "${GDB:-false}" = true ]; then
	export INTERACTIVE=true
fi

if [ "${INTERACTIVE:-false}" = true ] && [ -z "${SMOKE_TMUX_SOCK:-}" ]; then
	export SMOKE_TMUX_SOCK="grout-smoke-$$"
	exec tmux -L "$SMOKE_TMUX_SOCK" new-session -n test "$0" "$@"
fi

ip link set lo up

: "${test_frr:=false}"

: "${run_frr:=true}"

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

pause_for_debug() {
	if [ "${INTERACTIVE:-false}" = true ]; then
		if [ "$status" -ne 0 ]; then
			echo "Test FAILED (status=$status)." >/dev/tty
		else
			echo "Test PASSED." >/dev/tty
		fi
		echo "Debug windows are available. Press Enter to cleanup..." >/dev/tty
		read -r </dev/tty
		return
	fi
	if [ "${status:-0}" -eq 0 ]; then
		return
	fi
	if ! [ "${PAUSE_ON_FAILURE:-false}" = true ]; then
		return
	fi

	echo >/dev/tty
	[ -n "${SMOKE_LOG:-}" ] && [ -f "$SMOKE_LOG" ] && cat "$SMOKE_LOG" >/dev/tty
	echo >/dev/tty
	echo "Test failed. To debug, run:" >/dev/tty
	echo "  grcli -s $GROUT_SOCK_PATH" >/dev/tty
	echo >/dev/tty
	echo "Press Enter to continue cleanup or Ctrl-C to abort..." >/dev/tty
	read -r </dev/tty
}

stop_grout() {
	for name in "${tmux_windows[@]}"; do
		tmux kill-window -t "$name"
	done
	kill %?grcli
	wait %?grcli

	if [ "$run_grout" = false ]; then
		return
	fi

	kill -TERM "$grout_pid"

	set +x
	echo "Waiting for grout (PID $grout_pid) to terminate ..."
	wait "$grout_pid"
	local ret="$?"

	if [ "${GDB:-false}" = true ]; then
		tmux kill-window -t gdb
	fi

	if [ "$ret" -ne 0 ]; then
		status="$ret"
		if [ "$ret" -gt 128 ]; then
			local sig=$((ret - 128))
			echo "fail: grout terminated by signal SIG$(kill -l $sig)"
		else
			echo "fail: grout exited with an error status $ret"
		fi >&2
		coredumpctl debug --no-pager -q "$grout_pid" \
			--debugger-arguments="-batch -ex 'thread apply all bt'"
	fi
	set -x
}

cleanup() {
	status="$?"
	set +e

	pause_for_debug

	sh -x $tmp/cleanup

	if socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH 2>/dev/null; then
		# delete all non-port, non-bond, non-vrf interfaces first
		grcli interface show |
		grep -Ev -e ^NAME -e '\<port[[:space:]]+devargs=' -e '\<bond\>' -e '\<vrf\>' |
		while read -r name _; do
			grcli interface del "$name"
		done
		# then delete all ports and bonds
		grcli interface show |
		grep -ve ^NAME -e '\<vrf\>' |
		while read -r name _; do
			grcli interface del "$name"
		done
		# finally delete VRFs
		grcli interface show |
		grep -e '\<vrf\>' |
		while read -r name _; do
			grcli interface del "$name"
		done
	fi
	[ -s $tmp/restore_interfaces ] && sh -x $tmp/restore_interfaces

	stop_grout

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
tmux_windows=()

smoke_setenv() {
	export "$1=$2"
	if [ "${INTERACTIVE:-false}" = true ]; then
		tmux set-environment "$1" "$2"
	fi
}

tmux_new_window() {
	local name="$1"
	shift
	tmux new-window -d -n "$name" "$@"
	tmux_windows+=("$name")
}

netns_add() {
	local ns="$1"
	ip netns add "$ns"
	cat >> $tmp/cleanup <<EOF
ip netns pids "$ns" | xargs -r kill --timeout 500 KILL
ip netns del "$ns"
EOF
	ip -n "$ns" link set lo up
	if [ "${INTERACTIVE:-false}" = true ]; then
		tmux_new_window "$ns" ip netns exec "$ns" bash
	fi
}

move_to_netns() {
	local iface="$1"
	local netns="$2"

	ip link set "$iface" netns "$netns"
	ip -n "$netns" link set "$iface" up

	SECONDS=0 # will be automatically incremented by bash
	while ! ip -n "$netns" link show "$iface" | grep -qw LOWER_UP; do
		if [ "$SECONDS" -gt 5 ]; then
			fail "$iface link was not LOWER_UP after 5 seconds"
		fi
		sleep 0.2
	done
}

tap_counter=0
port_add() {
	local name="$1"
	shift
        if [ "$use_hardware_ports" = true ]; then
                if [ $tap_counter -ge ${#net_interfaces[@]} ]; then
			fail "Can not create port. No more hardware ports available."
		fi
		ip -n host link set "${net_interfaces[$tap_counter]}" netns $$
		ip link set "${net_interfaces[$tap_counter]}" name "x-$name"
                # When test fails prematurely due to insufficient number of ports
                # we need to return them back to default namespace and wait a little
                # before proceeding to ensure reliable execution
		echo "ip link set x-$name netns host || :" >> $tmp/restore_interfaces
		echo "sleep 1" >> $tmp/restore_interfaces
		# When a namespace is deleted while a renamed kernel interface
		# is inside it an 'altname' property with the interface original
		# name is created. This causes an error on attempt to restore
		# the original name. So we need to clear this 'altname' first.
		echo "ip -n host link property del dev x-$name altname ${net_interfaces[$tap_counter]} || :" >> $tmp/restore_interfaces
		echo "ip -n host link set x-$name name ${net_interfaces[$tap_counter]} || :" >> $tmp/restore_interfaces
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
	smoke_setenv GROUT_SOCK_PATH "$tmp/grout.sock"
fi
if [ -n "${builddir}" ]; then
	smoke_setenv PATH "$builddir:$PATH"
fi

grout_extra_options=""
if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	grout_extra_options+="-m 0666"
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
	smoke_setenv ASAN_OPTIONS disable_coredump=0
	if [ "$use_hardware_ports" = false ]; then
		grout_extra_options+=" -t"
	fi
	# try to spread load on all CPUs
	cpu="$(($RANDOM % ($(nproc) - 1)))"
	affinity="$cpu,$((cpu+1))"
	local_grout_cmd="taskset -c $affinity grout -vvx $grout_extra_options"
	if [ "${GDB:-false}" = true ]; then
		tmux new-window -d -n gdb gdb \
			-ex 'handle SIGTERM nostop print pass' \
			--args $local_grout_cmd
	elif [ -t 1 ]; then
		# print grout logs in blue (stderr in bold red)
		$local_grout_cmd \
			> >(awk '{print "\033[34m" $0 "\033[0m"}') \
			2> >(awk '{print "\033[1;31m" $0 "\033[0m"}' >&2) &
		grout_pid=$!
	else
		$local_grout_cmd &
		grout_pid=$!
	fi
fi
if [ "${GDB:-false}" = true ]; then
	echo "Waiting for gdb start. Switch to the grout window and configure breakpoints."
	socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH,forever
	gdb_pid=$(tmux list-windows -F '#{window_name} #{pane_pid}' | awk '/gdb/{print $2}')
	grout_pid=$(pgrep -P $gdb_pid | head -n1)
else
	SECONDS=0
	while ! socat FILE:/dev/null UNIX-CONNECT:$GROUT_SOCK_PATH 2>/dev/null; do
		if [ "$SECONDS" -gt 30 ]; then
			fail "grout took more than 30s to start"
		fi
		kill -0 "$grout_pid"
		sleep 1
	done
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

if [ "${INTERACTIVE:-false}" = true ]; then
	tmux_new_window grcli grcli
fi
