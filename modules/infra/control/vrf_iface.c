// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_iface.h>
#include <gr_kernel.h>

static void iface_vrf_to_api(void * /* info */, const struct iface * /* iface */) { }

static struct iface_type iface_type_vrf = {
	.id = GR_IFACE_TYPE_VRF,
	.name = "vrf",
	.info_size = sizeof(struct iface_info_kernel),
	.init = iface_kernel_init,
	.fini = iface_kernel_fini,
	.to_api = iface_vrf_to_api,
};

RTE_INIT(vrf_iface_constructor) {
	iface_type_register(&iface_type_vrf);
}
