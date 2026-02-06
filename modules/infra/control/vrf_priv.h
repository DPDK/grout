// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_iface.h>
#include <gr_loopback.h>

GR_IFACE_INFO(GR_IFACE_TYPE_VRF, iface_info_vrf, {
	BASE(gr_iface_info_vrf);
	struct iface_info_loopback lo;
});

// Increment VRF reference count.
// vrf_id is the VRF interface ID.
// Returns 0 on success, -1 if VRF doesn't exist (sets errno to ENONET).
int vrf_incref(uint16_t vrf_id);

// Decrement VRF reference count.
// vrf_id is the VRF interface ID.
void vrf_decref(uint16_t vrf_id);

// Create kernel VRF and register VRF interface.
// Called from VRF init. Uses iface->id as VRF identifier.
int vrf_add(struct iface *loop_iface);

// Delete kernel VRF and unregister.
// Called from VRF fini. vrf_id is the VRF interface ID.
int vrf_del(uint16_t vrf_id);

// Check if VRF has any interfaces (ref_count > 0).
// vrf_id is the VRF interface ID.
bool vrf_has_interfaces(uint16_t vrf_id);

// Check if the given interface is the auto-created default VRF.
bool vrf_is_default(const struct iface *iface);
