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
		printf 'gr-loop%s\n' "$vrf_id"
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
	# Expected "grcli route show" output pattern:
	# VRF  DESTINATION        NEXT_HOP
	# 0    fd00:202::100/128  type=SRv6-local id=12 iface=gr-loop0 vrf=0 origin=zebra behavior=end.dt4 out_vrf=0
	local grep_pattern="\\<${sid_local}/128[[:space:]]+type=SRv6-local\\>.*\\<behavior=${grout_behavior}\\>"
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
    # VRF  DESTINATION      NEXT_HOP
    # 0    192.168.0.0/16   type=SRv6 id=8 iface=geydsm1 vrf=0 origin=zebra h.encap fd00:202::2
    local sid_regex="${sids[0]}"
    for ((i=1; i<${#sids[@]}; i++)); do
	    sid_regex+="[[:space:]]+${sids[i]}"
    done
    local grep_pattern="\\<${prefix}[[:space:]]+type=SRv6\\>.*${sid_regex}"

    # ----- wait until Grout shows it --------------------------------------
    while ! grcli route show | grep -qE "${grep_pattern}"; do
	    if (( count++ >= max_tries )); then
		    echo "SRv6 route ${prefix} via ${seg_space} not visible in Grout after ${max_tries}s." >&2
		    exit 1
	    fi
	    sleep 0.2
    done
}
