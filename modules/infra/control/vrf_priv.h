// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <stdbool.h>
#include <stdint.h>

struct iface;

// Increment VRF reference count.
// vrf_id is the loopback interface ID.
// Returns 0 on success, -1 if VRF doesn't exist (sets errno to ENONET).
int vrf_incref(uint16_t vrf_id);

// Decrement VRF reference count.
// vrf_id is the loopback interface ID.
void vrf_decref(uint16_t vrf_id);

// Create kernel VRF and register loopback interface.
// Called from loopback init. Uses iface->id as VRF identifier.
int vrf_add(struct iface *loop_iface);

// Delete kernel VRF and unregister.
// Called from loopback fini. vrf_id is the loopback interface ID.
int vrf_del(uint16_t vrf_id);

// Rename the kernel VRF or TUN device.
// vrf_id is the loopback interface ID.
int vrf_rename(uint16_t vrf_id, const char *new_name);

// Check if VRF has any interfaces (ref_count > 0).
// vrf_id is the loopback interface ID.
bool vrf_has_interfaces(uint16_t vrf_id);
