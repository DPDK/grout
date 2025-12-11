// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>

#include <stdlib.h>
#include <string.h>

static struct api_out l2_bridge_add_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_add_req *req = request;
	struct bridge_info *bridge;
	struct gr_l2_bridge *resp;

	bridge = bridge_add(req->name, &req->config);

	if (bridge == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = malloc(sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	bridge_to_api(resp, bridge);
	return api_out(0, sizeof(*resp), resp);
}

static struct api_out l2_bridge_del_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_del_req *req = request;
	int ret;

	ret = bridge_del(req->bridge_id);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out l2_bridge_list_api(const void *request __rte_unused, struct api_ctx *ctx) {
	struct bridge_info *bridge;
	uint16_t bridge_id = 0;

	while ((bridge = bridge_get_next(&bridge_id)) != NULL) {
		struct gr_l2_bridge bridge_data;
		bridge_to_api(&bridge_data, bridge);
		api_send(ctx, sizeof(bridge_data), &bridge_data);
	}

	return api_out(0, 0, NULL);
}

static struct api_out l2_bridge_get_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_get_req *req = request;
	struct bridge_info *bridge;
	struct gr_l2_bridge *resp;
	uint16_t bridge_id = 0;

	if (req->bridge_id != GR_BRIDGE_ID_UNDEF) {
		bridge = bridge_get(req->bridge_id);
	} else {
		while ((bridge = bridge_get_next(&bridge_id)) != NULL) {
			if (strncmp(bridge->name, req->name, sizeof(req->name)) == 0)
				break;
		}
	}
	if (bridge == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = malloc(sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	bridge_to_api(resp, bridge);
	return api_out(0, sizeof(*resp), resp);
}

// Bridge member API handlers
static struct api_out
l2_bridge_member_add_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_member_add_req *req = request;
	int ret;

	ret = bridge_member_add(req->bridge_id, req->iface_id);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out
l2_bridge_member_del_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_member_del_req *req = request;
	int ret;

	ret = bridge_member_del(req->bridge_id, req->iface_id);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out l2_bridge_member_list_api(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_bridge_member_list_req *req = request;
	struct bridge_info *bridge;
	struct iface *iface;
	uint16_t *member;

	bridge = bridge_get(req->bridge_id);
	if (bridge == NULL)
		return api_out(ENOENT, 0, NULL);

	gr_vec_foreach_ref (member, bridge->members) {
		iface = iface_from_id(*member);
		if (iface == NULL)
			continue;

		struct gr_l2_bridge_member member_data = {
			.bridge_id = req->bridge_id,
			.iface_id = *member,
		};
		strncpy(member_data.iface_name, iface->name, sizeof(member_data.iface_name) - 1);
		member_data.iface_name[sizeof(member_data.iface_name) - 1] = '\0';

		api_send(ctx, sizeof(member_data), &member_data);
	}

	return api_out(0, 0, NULL);
}

// Bridge config API handlers
static struct api_out
l2_bridge_config_get_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_config_get_req *req = request;
	struct gr_l2_bridge_config *resp;
	int ret;

	resp = malloc(sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	ret = bridge_config_get(req->bridge_id, resp);
	if (ret < 0) {
		free(resp);
		return api_out(errno, 0, NULL);
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out
l2_bridge_config_set_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_bridge_config_set_req *req = request;
	int ret;

	ret = bridge_config_set(req->bridge_id, &req->config);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

// MAC table API handlers
static struct api_out l2_mac_add_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_mac_add_req *req = request;
	int ret;

	ret = mac_entry_add(req->bridge_id, req->iface_id, &req->mac, req->type);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out l2_mac_del_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_mac_del_req *req = request;
	int ret;

	ret = mac_entry_del(req->bridge_id, &req->mac);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out l2_mac_list_api(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_mac_list_req *req = request;
	struct bridge_info *bridge;
	struct mac_entry *entry;
	uint16_t bridge_id;

	if (req->bridge_id != 0) {
		// List entries for specific bridge
		entry = NULL;
		while ((entry = mac_entry_get_next(req->bridge_id, entry)) != NULL) {
			struct gr_l2_mac_entry mac_data;
			mac_entry_to_api(&mac_data, entry);
			api_send(ctx, sizeof(mac_data), &mac_data);
		}
	} else {
		// List entries for all bridges
		bridge_id = 0;
		while ((bridge = bridge_get_next(&bridge_id)) != NULL) {
			entry = NULL;
			while ((entry = mac_entry_get_next(bridge_id, entry)) != NULL) {
				struct gr_l2_mac_entry mac_data;
				mac_entry_to_api(&mac_data, entry);
				api_send(ctx, sizeof(mac_data), &mac_data);
			}
		}
	}

	return api_out(0, 0, NULL);
}

static struct api_out l2_mac_flush_api(const void *request, struct api_ctx *ctx __rte_unused) {
	const struct gr_l2_mac_flush_req *req = request;
	int ret;

	ret = mac_table_flush(req->bridge_id, req->iface_id, req->dynamic_only);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

// API handler registration
static struct gr_api_handler bridge_add_handler = {
	.name = "l2 bridge add",
	.request_type = GR_L2_BRIDGE_ADD,
	.callback = l2_bridge_add_api,
};

static struct gr_api_handler bridge_del_handler = {
	.name = "l2 bridge del",
	.request_type = GR_L2_BRIDGE_DEL,
	.callback = l2_bridge_del_api,
};

static struct gr_api_handler bridge_list_handler = {
	.name = "l2 bridge list",
	.request_type = GR_L2_BRIDGE_LIST,
	.callback = l2_bridge_list_api,
};

static struct gr_api_handler bridge_get_handler = {
	.name = "l2 bridge get",
	.request_type = GR_L2_BRIDGE_GET,
	.callback = l2_bridge_get_api,
};

static struct gr_api_handler mac_add_handler = {
	.name = "l2 mac add",
	.request_type = GR_L2_MAC_ADD,
	.callback = l2_mac_add_api,
};

static struct gr_api_handler mac_del_handler = {
	.name = "l2 mac del",
	.request_type = GR_L2_MAC_DEL,
	.callback = l2_mac_del_api,
};

static struct gr_api_handler mac_list_handler = {
	.name = "l2 mac list",
	.request_type = GR_L2_MAC_LIST,
	.callback = l2_mac_list_api,
};

static struct gr_api_handler bridge_member_add_handler = {
	.name = "l2 bridge member add",
	.request_type = GR_L2_BRIDGE_MEMBER_ADD,
	.callback = l2_bridge_member_add_api,
};

static struct gr_api_handler bridge_member_del_handler = {
	.name = "l2 bridge member del",
	.request_type = GR_L2_BRIDGE_MEMBER_DEL,
	.callback = l2_bridge_member_del_api,
};

static struct gr_api_handler bridge_member_list_handler = {
	.name = "l2 bridge member list",
	.request_type = GR_L2_BRIDGE_MEMBER_LIST,
	.callback = l2_bridge_member_list_api,
};

static struct gr_api_handler bridge_config_get_handler = {
	.name = "l2 bridge config get",
	.request_type = GR_L2_BRIDGE_CONFIG_GET,
	.callback = l2_bridge_config_get_api,
};

static struct gr_api_handler bridge_config_set_handler = {
	.name = "l2 bridge config set",
	.request_type = GR_L2_BRIDGE_CONFIG_SET,
	.callback = l2_bridge_config_set_api,
};

static struct gr_api_handler mac_flush_handler = {
	.name = "l2 mac flush",
	.request_type = GR_L2_MAC_FLUSH,
	.callback = l2_mac_flush_api,
};

RTE_INIT(l2_api_handlers_init) {
	gr_register_api_handler(&bridge_add_handler);
	gr_register_api_handler(&bridge_del_handler);
	gr_register_api_handler(&bridge_list_handler);
	gr_register_api_handler(&bridge_get_handler);
	gr_register_api_handler(&bridge_member_add_handler);
	gr_register_api_handler(&bridge_member_del_handler);
	gr_register_api_handler(&bridge_member_list_handler);
	gr_register_api_handler(&bridge_config_get_handler);
	gr_register_api_handler(&bridge_config_set_handler);
	gr_register_api_handler(&mac_add_handler);
	gr_register_api_handler(&mac_del_handler);
	gr_register_api_handler(&mac_list_handler);
	gr_register_api_handler(&mac_flush_handler);
}
