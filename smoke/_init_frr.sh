# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Maxime Leroy, Free Mobile

test_frr=true

. $(dirname $0)/_init.sh

tap_index=0
create_interface() {
	local p="$1"
	local mac="$2"

	ip link add v0-$p type veth peer name v1-$p
	grcli add interface port $p devargs net_tap$tap_index,iface=tap-$p,remote=v0-$p mac $mac

	local max_tries=5
	local count=0
	while vtysh -c "show interface $p" 2>&1 | grep -q "% Can't find interface"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Interface $p not found after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done

	tap_index=$((tap_index + 1))
}

set_ip_address() {
	local p="$1"
	local ip_cidr="$2"
	local max_tries=5
	local count=0

	if echo "$ip_cidr" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
		local gr_ip="ip6"
	else
		# IPv4
		local frr_ip="ip"
		local gr_ip="ip"
	fi

	local grep_pattern="^${p}[[:space:]]\+${ip_cidr}$"

	vtysh <<-EOF
	configure terminal
	interface ${p}
	${frr_ip} address ${ip_cidr}
	exit
EOF

	while ! grcli show ${gr_ip} address | grep -q "$grep_pattern"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "IP address $ip_cidr not set after $max_tries attempts."
			exit 1
		fi
		sleep 1
		count=$((count + 1))
	done
}

set_ip_route() {
	local prefix="$1"
	local next_hop="$2"
	local max_tries=5
	local count=0

	if echo "$prefix" | grep -q ':'; then
		# IPv6
		local frr_ip="ipv6"
		local gr_ip="ip6"
	else
		# IPv4
		local frr_ip="ip"
		local gr_ip="ip"
	fi

	local grep_pattern="^0[[:space:]]\+${prefix}[[:space:]]\+${next_hop}[[:space:]]"

	vtysh <<-EOF
	configure terminal
	${frr_ip} route ${prefix} ${next_hop}
	exit
EOF

	while ! grcli show ${gr_ip} route | grep -q "${grep_pattern}"; do
		if [ "$count" -ge "$max_tries" ]; then
			echo "Route ${prefix} via ${next_hop} not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 1
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
		end.dt4)  frr_behavior="uDT4" ;;
		end.dt6)  frr_behavior="uDT6" ;;
		end.dt46) frr_behavior="uDT46" ;;
		*) echo "Unsupported behavior '${grout_behavior}'. Use end.dt4, end.dt6, end.dt46."; exit 1 ;;
	esac

	# --- push the config into FRR ------------------------------------------
	vtysh <<-EOF
	configure terminal
	 segment-routing
	  srv6
	   locators
	    locator ${locator}
	     prefix ${sid_prefix}::/32 block-len 16 node-len 16 func-bits 0
	    exit
	   exit
	   static-sids
	    sid ${sid_local}/128 locator ${locator} behavior ${frr_behavior} vrf default
	   exit
	 exit
EOF

	# --- wait until grout has the localsid ---------------------------------
	# Expected "grcli show sr localsid" output pattern:
	# vrf lsid                         behavior  args
	# 0   fc00:100:64:10::666          end.dt4   out_vrf=0
	local grep_pattern="^[[:space:]]*0[[:space:]]+${sid_local}[[:space:]]+${grout_behavior}"

	while ! grcli show sr localsid | grep -qE "${grep_pattern}"; do
		if [ "$count" -ge "$max_tries" ]; then
			grcli show sr localsid
			echo "SRv6 localsid ${sid_local} (${grout_behavior}) not found after ${max_tries} attempts."
			exit 1
		fi
		sleep 1
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
	    frr_ip="ipv6"; gr_ip="ip6"
    else
	    frr_ip="ip";   gr_ip="ip"
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
    local sid_regex="${sids[0]}"
    for ((i=1; i<${#sids[@]}; i++)); do
	    sid_regex+="[[:space:]]\\+${sids[i]}"
    done
    local grep_pattern="^[[:space:]]*0[[:space:]]\\+${prefix}[[:space:]]\\+h\\.encap[[:space:]]\\+${sid_regex}"

    # ----- wait until Grout shows it --------------------------------------
    while ! grcli show sr route | grep -q "${grep_pattern}"; do
	    if (( count++ >= max_tries )); then
		    echo "SRv6 route ${prefix} via ${seg_space} not visible in Grout after ${max_tries}s." >&2
		    exit 1
	    fi
	    sleep 1
    done
}
