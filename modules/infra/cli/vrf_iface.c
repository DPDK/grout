// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>

static void vrf_show(const struct gr_api_client *, const struct gr_iface *) { }

static void vrf_list_info(const struct gr_api_client *, const struct gr_iface *, char *, size_t) { }

static struct cli_iface_type vrf_type = {
	.type_id = GR_IFACE_TYPE_VRF,
	.name = "vrf",
	.show = vrf_show,
	.list_info = vrf_list_info,
};

static void __attribute__((constructor, used)) init(void) {
	register_iface_type(&vrf_type);
}
