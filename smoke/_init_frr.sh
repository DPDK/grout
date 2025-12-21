# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

test_frr=true

. $(dirname $0)/_init.sh

create_interface() {
	local p="$1"
	shift
	local max_tries=5
	local count=0

	port_add $p "$@"

	while vtysh -c "show interface $p" 2>&1 | grep -q "% Can't find interface"; do
		if [ "$count" -ge "$max_tries" ]; then
			fail "Interface $p not found after $max_tries attempts."
		fi
		sleep 0.2
		count=$((count + 1))
	done
}

set_ip_address() {
	local p="$1"
	local ip_cidr="$2"
	local max_tries=5
	local count=0

	if echo "$ip_cidr" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
	else
		# IPv4
		local frr_ip="ip"
	fi

	local grep_pattern="^${p}[[:space:]]\+${ip_cidr}$"

	vtysh <<-EOF
	configure terminal
	interface ${p}
	${frr_ip} address ${ip_cidr}
	exit
EOF

	while ! grcli address show iface ${p} | grep -q "$grep_pattern"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "IP address $ip_cidr not set after $max_tries attempts."
			exit 1
		fi
		sleep 0.2
		count=$((count + 1))
	done
}

vrf_name_from_id() {
	local vrf_id="${1:-0}"

	if [[ "$vrf_id" -eq 0 ]]; then
		printf 'default\n'
	else
		printf 'gr-vrf%s\n' "$vrf_id"
	fi
}

set_vrf_iface() {
	local vrf_id="$1"
	local vrf_name="$(vrf_name_from_id "$vrf_id")"

	vtysh <<-EOF
	configure terminal
	interface ${vrf_name} vrf ${vrf_name}
	exit
EOF
}

set_ip_route() {
	local prefix="$1"
	local next_hop="$2"
	local vrf_id="${3:-0}"
	local nexthop_vrf_id="${4:-}"
	local max_tries=5
	local count=0
	local vrf_name="$(vrf_name_from_id "$vrf_id")"

	local nexthop_vrf_clause=""
	if [[ -n "$nexthop_vrf_id" ]]; then
		    local nexthop_vrf_name
		    nexthop_vrf_name="$(vrf_name_from_id "$nexthop_vrf_id")"
		    nexthop_vrf_clause=" nexthop-vrf ${nexthop_vrf_name}"
	fi

	if echo "$prefix" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
	else
		# IPv4
		local frr_ip="ip"
	fi

	local grep_pattern="^${vrf_id}[[:space:]]\\+${prefix}\\>.*\\<${next_hop}\\>"

	vtysh <<-EOF
	configure terminal
	${frr_ip} route ${prefix} ${next_hop} vrf ${vrf_name}${nexthop_vrf_clause}
	exit
EOF

	while ! grcli route show vrf ${vrf_id} | grep -q "${grep_pattern}"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Route ${prefix} via ${next_hop} not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 0.2
		count=$((count + 1))
	done
}

# set_srv6_localsid <locator> <sid-prefix> <sid-local> [behavior]
#
# Example:
#   set_srv6_localsid myloc fd00:202 fc00:100:64:10::666 end.dt4
#
set_srv6_localsid() {
	local locator="$1"
	local sid_prefix="$2"
	local sid_local="$3"
	local grout_behavior="${4:-end.dt4}"   # default behaviour
	local max_tries=5
	local count=0

	# ---- translate behaviour aliases --------------------------------------
	# map:  end.dt4 -> uDT4,  end.dt6 -> uDT6,  end.dt46 -> uDT46
	local frr_behavior
	case "${grout_behavior,,}" in           # ,, = lower-case
		end.dt4)  frr_behavior="End.DT4" ;;
		end.dt6)  frr_behavior="End.DT6" ;;
		end.dt46) frr_behavior="End.DT46" ;;
		*) echo "Unsupported behavior '${grout_behavior}'. Use end.dt4, end.dt6, end.dt46."; exit 1 ;;
	esac

	# --- push the config into FRR ------------------------------------------
	vtysh <<-EOF
	configure terminal
	 segment-routing
	  srv6
	   locators
	    locator ${locator}
	     prefix ${sid_prefix}::/32 block-len 16 node-len 16 func-bits 16
	    exit
	   exit
	   static-sids
	    sid ${sid_local}/48 locator ${locator} behavior ${frr_behavior} vrf default
	   exit
	 exit
EOF

	# --- wait until grout has the localsid ---------------------------------
	# Expected "grcli route show" output pattern:
	# VRF  DESTINATION        ORIGIN        NEXT_HOP
	# 0    fd00:202::100/48  zebra_static  type=SRv6-local id=12 .... behavior=end.dt4 ...
	local grep_pattern="\\<${sid_local}/48\\>.+\\<type=SRv6-local\\>.*\\<behavior=${grout_behavior}\\>"
	while ! grcli route show | grep -qE "${grep_pattern}"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "SRv6 localsid ${sid_local} (${grout_behavior}) not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 0.2
		count=$((count + 1))
	done
}

# set_srv6_route <prefix> <next-hop|iface> <sid1> [sid2 sid3 …]
#
# EXAMPLE
#   # Three SIDs provided as separate arguments
#   set_srv6_route 192.168.0.0/16 gmydsn1 \
#       fd00:202::2 fd00:202::3 fd00:202::4
#
set_srv6_route() {
    local prefix="$1"
    local nhop="$2"
    local max_tries=5
    local count=0
    shift 2                       # all remaining words are SIDs (and maybe max_tries)

    # ----- collect SIDs ----------------------------------------------------
    local sids=()
    while [[ "$1" =~ : ]]; do     # anything with a ":" is assumed to be a SID
	    sids+=("$1")
	    shift
    done
    [[ ${#sids[@]} -eq 0 ]] && { echo "set_srv6_route: need at least one SID" >&2; return 1; }

    # ----- choose FRR keyword ---------------------------------------------
    local frr_ip gr_ip
    if [[ "$prefix" == *:* ]]; then
	    frr_ip="ipv6"
    else
	    frr_ip="ip"
    fi

    # ----- build CLI & Grout forms ----------------------------------------
    local seg_frr   ; IFS=/ ; seg_frr="${sids[*]}"       # SID/SID/…
    local seg_space ; IFS=' ' ; seg_space="${sids[*]}"   # SID SID …

    # ----- push route into FRR --------------------------------------------
    vtysh <<-EOF
    configure terminal
      ${frr_ip} route ${prefix} ${nhop} segments ${seg_frr}
      exit
EOF

    # ----- make BRE pattern for Grout -------------------------------------
    # Expected output from grcli route show
    #
    # VRF  DESTINATION      ORIGIN        NEXT_HOP
    # 0    192.168.0.0/16   zebra_static  type=SRv6 id=6 iface=p1 vrf=0 ...
    local sid_regex="${sids[0]}"
    for ((i=1; i<${#sids[@]}; i++)); do
	    sid_regex+="[[:space:]]+${sids[i]}"
    done
    local grep_pattern="\\<${prefix}\\>.+\\<type=SRv6\\>.*${sid_regex}"

    # ----- wait until Grout shows it --------------------------------------
    while ! grcli route show | grep -qE "${grep_pattern}"; do
	    if (( count++ >= max_tries )); then
		    echo "SRv6 route ${prefix} via ${seg_space} not visible in Grout after ${max_tries}s." >&2
		    exit 1
	    fi
	    sleep 0.2
    done
}

#   <namespace> : optional netns name ("" = root namespace)
#   <use_grout> : "1" -> enable dplane_grout, anything else -> no grout
start_frr() {
	local namespace="$1"
	local use_grout="$2"

	local frr_etc="$builddir/frr_install/etc/frr"
	local frr_logdir="$builddir/frr_install/var/log/frr"
	local conf_dir flog daemons_file frrconf_file frr_global_opts
	local zebra_options="-s 90000000"

	mkdir -p "$frr_etc"
	mkdir -p "$frr_logdir"

	# Common config dir + files + log file + opts
	conf_dir="$frr_etc${namespace:+/$namespace}"
	flog="$frr_logdir/frr-${namespace:-grout}.log"

	mkdir -p "$conf_dir"
	touch "$conf_dir/vtysh.conf"

	daemons_file="$conf_dir/daemons"
	frrconf_file="$conf_dir/frr.conf"
	frr_global_opts="-A 127.0.0.1 --log file:$flog"

	if [ "$use_grout" = "1" ]; then
		zebra_options="$zebra_options -M dplane_grout"
	fi

	# daemons
	cat >"$daemons_file" <<EOF
bgpd=yes
isisd=yes
ospfd=yes
ospf6d=yes
vtysh_enable=yes
frr_global_options="$frr_global_opts"
zebra_options="$zebra_options"
EOF

	# only namespaces use watchfrr in a netns
	if [ -n "$namespace" ]; then
		cat >>"$daemons_file" <<EOF
watchfrr_options="--netns=$namespace"
EOF
	fi

	# frr.conf
	cat >"$frrconf_file" <<EOF
hostname ${namespace:-grout}
EOF

	# reset log
	rm -f "$flog"
	touch "$flog"

	# logging: root strips ts, ns gets [ns] prefix
	local sed_expr color
	if [ -n "$namespace" ]; then
		sed_expr="s,^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[$namespace],"
		color="\033[32m"
	else
		sed_expr="s,^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} ,,"
		color="\033[35m"
	fi

	if [ -t 1 ]; then
		tail -F "$flog" | sed -E "$sed_expr" | awk -v color="$color" '{print color $0 "\033[0m"}' &
	else
		tail -F "$flog" | sed -E "$sed_expr" &
	fi
	local tailpid=$!

	if [ -n "$namespace" ]; then
		nsenter -t 1 -n -m ip netns add "$namespace"
	fi

	# cleanup
	cat >>"$tmp/cleanup" <<EOF
frrinit.sh stop ${namespace:+$namespace}
kill $tailpid 2>/dev/null || true
EOF
	if [ -n "$namespace" ]; then
		cat >>"$tmp/cleanup" <<EOF
nsenter -t 1 -n -m ip netns pids "$namespace" | xargs -r kill --timeout 500 KILL
nsenter -t 1 -n -m ip netns del "$namespace"
EOF
	fi

	# start FRR
	frrinit.sh start ${namespace:+$namespace}

	# wait for all daemons (staticd is always started by FRR init)
	local daemon pattern
	for daemon in staticd bgpd isisd ospfd ospf6d; do
		SECONDS=0
		pattern="$daemon"
		[ -n "$namespace" ] && pattern="$daemon -N $namespace"

		while ! pgrep -f "$pattern" >/dev/null 2>&1; do
			if [ "$SECONDS" -ge 5 ]; then
				if [ -n "$namespace" ]; then
					fail "$daemon daemon not started for namespace $namespace"
				else
					fail "$daemon daemon not started"
				fi
			fi
			sleep 0.1
		done
	done

	# extra check when using Grout: wait for iface/ip events
	if [ "$use_grout" = "1" ]; then
		local attempts=25
		while ! grep -q "GROUT:.*iface/ip events" "$flog" 2>/dev/null; do
			if [ "$attempts" -le 0 ]; then
				fail "Zebra is not listening grout events."
			fi
			sleep 0.2
			attempts=$((attempts - 1))
		done
	fi
}

if [ "$test_frr" = true ] && [ "$run_frr" = true ]; then
	chmod 0777 $tmp # to access on tmp

	if [ -n "${builddir}" ]; then
		export PATH=$builddir/frr_install/sbin:$builddir/frr_install/bin:$PATH
	fi

	export ZEBRA_DEBUG_DPLANE_GROUT=1
	start_frr "" 1
fi
