// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Robin Jarry

// L3VNI dplane-thread state for EVPN symmetric IRB (Integrated Routing and
// Bridging).
//
// FRR's EVPN type-5 (IP prefix) routes use a per-VRF L3 VNI with a VXLAN
// interface. Two mappings are maintained on the dplane thread (no locking):
//
// VRF -> VXLAN iface
//
//   grout_add_nexthop() redirects nexthops from the VRF (FRR's SVI model) to
//   the VXLAN interface so that ip_output routes packets into the tunnel.
//
// (VRF, VTEP) -> RMAC
//
//   DPLANE_OP_NEIGH_INSTALL delivers the remote router MAC before
//   DPLANE_OP_NH_INSTALL creates the nexthop. The RMAC is cached here and
//   applied by grout_add_nexthop() when the nexthop arrives.

#pragma once

#include "lib/prefix.h"

#include <gr_net_types.h>

#include <stdint.h>

// Register vrf_id -> vxlan_iface_id mapping.
void l3vni_set(uint16_t vrf_id, uint16_t vxlan_iface_id);

// Remove mapping for vrf_id.
void l3vni_del(uint16_t vrf_id);

// Return vxlan iface id for vrf_id, or GR_IFACE_ID_UNDEF.
uint16_t l3vni_get_vxlan(uint16_t vrf_id);

// Cache remote VTEP router MAC for (vrf_id, vtep).
void l3vni_rmac_set(uint16_t vrf_id, ip4_addr_t vtep, const struct ethaddr *mac);

// Remove cached RMAC for (vrf_id, vtep).
void l3vni_rmac_del(uint16_t vrf_id, ip4_addr_t vtep);

// Look up cached RMAC for (vrf_id, vtep), or NULL.
const struct ethaddr *l3vni_rmac_get(uint16_t vrf_id, ip4_addr_t vtep);
