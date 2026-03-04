// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_display.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

static STAILQ_HEAD(, cli_iface_type) types = STAILQ_HEAD_INITIALIZER(types);

struct iface_cache_item {
	bool valid;
	gr_iface_type_t type;
	char name[IFNAMSIZ];
};

struct iface_cache {
	struct iface_cache_item items[GR_MAX_IFACES];
};

static struct iface_cache *iface_cache_get(struct gr_api_client *c) {
	struct iface_cache *cache = gr_api_client_get_priv(c);
	if (cache == NULL) {
		cache = calloc(1, sizeof(*cache));
		gr_api_client_set_priv(c, cache);
	}
	return cache;
}

static struct iface_cache_item *
iface_cache_update(struct gr_api_client *c, const struct gr_iface *iface) {
	struct iface_cache *cache = iface_cache_get(c);
	struct iface_cache_item *item;

	assert(iface != NULL);
	assert(cache != NULL);
	assert(iface->id < ARRAY_DIM(cache->items));

	item = &cache->items[iface->id];
	item->valid = true;
	item->type = iface->type;
	snprintf(item->name, sizeof(item->name), "%s", iface->name);

	return item;
}

static void iface_cache_del(struct gr_api_client *c, uint16_t ifid) {
	struct iface_cache *cache = iface_cache_get(c);
	assert(cache != NULL);

	assert(ifid < ARRAY_DIM(cache->items));

	memset(&cache->items[ifid], 0, sizeof(cache->items[ifid]));
}

void register_iface_type(struct cli_iface_type *type) {
	assert(type != NULL);
	assert(type->list_info != NULL);
	assert(type->show != NULL);
	STAILQ_INSERT_TAIL(&types, type, next);
}

const struct cli_iface_type *type_from_name(const char *name) {
	const struct cli_iface_type *type;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	STAILQ_FOREACH (type, &types, next) {
		if (strcmp(gr_iface_type_name(type->type_id), name) == 0)
			return type;
	}
	errno = ENODEV;
	return NULL;
}

int complete_iface_types(
	struct gr_api_client *,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const struct cli_iface_type *type;

	STAILQ_FOREACH (type, &types, next) {
		const char *name = gr_iface_type_name(type->type_id);
		if (!ec_str_startswith(name, arg))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, name))
			return -errno;
	}
	return 0;
}
const struct cli_iface_type *type_from_id(gr_iface_type_t type_id) {
	const struct cli_iface_type *type;

	STAILQ_FOREACH (type, &types, next) {
		if (type->type_id == type_id)
			return type;
	}
	errno = ENODEV;
	return NULL;
}

int complete_iface_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
) {
	struct gr_iface_list_req req = {.type = GR_IFACE_TYPE_UNDEF};
	const struct iface_cache *cache = iface_cache_get(c);
	gr_iface_type_t type = (uintptr_t)cb_arg;
	const struct gr_iface *iface;
	unsigned cached;
	int result = 0;
	int ret;

again:
	cached = 0;
	for (unsigned i = 0; i < ARRAY_DIM(cache->items); i++) {
		const struct iface_cache_item *item = &cache->items[i];
		if (!item->valid)
			continue;
		cached++;
		if (type != GR_IFACE_TYPE_UNDEF && item->type != type)
			continue;
		if (!ec_str_startswith(item->name, arg))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, item->name))
			result = -1;
	}
	if (cached > 0)
		return result;

	gr_api_client_stream_foreach (iface, ret, c, GR_IFACE_LIST, sizeof(req), &req) {
		iface_cache_update(c, iface);
		cached++;
	}
	if (cached > 0)
		goto again;

	return ret;
}

int complete_vrf_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	return complete_iface_names(c, node, comp, arg, INT2PTR(GR_IFACE_TYPE_VRF));
}

int arg_iface(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	const char *id,
	gr_iface_type_t type,
	uint16_t *iface_id
) {
	const char *name = arg_str(p, id);
	if (name == NULL)
		return -errno;

	struct gr_iface *iface = iface_from_name(c, name);
	if (iface == NULL)
		return -errno;

	if (type != GR_IFACE_TYPE_UNDEF && iface->type != type) {
		free(iface);
		return errno_set(EMEDIUMTYPE);
	}

	*iface_id = iface->id;
	free(iface);
	return 0;
}

int arg_vrf(struct gr_api_client *c, const struct ec_pnode *p, const char *id, uint16_t *vrf_id) {
	int ret = arg_iface(c, p, id, GR_IFACE_TYPE_VRF, vrf_id);
	if (ret == -ENOENT) {
		*vrf_id = GR_VRF_DEFAULT_ID;
		ret = 0;
	}
	return ret;
}

struct gr_iface *iface_from_name(struct gr_api_client *c, const char *name) {
	struct gr_iface_get_req req = {.iface_id = GR_IFACE_ID_UNDEF};
	void *resp_ptr = NULL;

	if (name == NULL)
		return errno_set_null(EINVAL);

	memccpy(req.name, name, 0, sizeof(req.name));

	if (gr_api_client_send_recv(c, GR_IFACE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return NULL;

	iface_cache_update(c, resp_ptr);
	return resp_ptr;
}

struct gr_iface *iface_from_id(struct gr_api_client *c, uint16_t iface_id) {
	struct gr_iface_get_req req = {.iface_id = iface_id, .name = ""};
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_IFACE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return NULL;

	iface_cache_update(c, resp_ptr);
	return resp_ptr;
}

const char *iface_name_from_id(struct gr_api_client *c, uint16_t ifid) {
	const struct iface_cache_item *item;
	const struct iface_cache *cache;

	if (ifid == GR_IFACE_ID_UNDEF)
		return "";
	if (ifid >= GR_MAX_IFACES)
		return "[???]";

	cache = iface_cache_get(c);
	if (cache == NULL)
		return "[nomem]";

	item = &cache->items[ifid];
	if (item->valid)
		return item->name;

	struct gr_iface *iface = iface_from_id(c, ifid);
	if (iface == NULL)
		return "[deleted]";
	item = iface_cache_update(c, iface);
	free(iface);

	return item->name;
}

static ssize_t iface_flags_format(char *buf, size_t len, const struct gr_iface *iface) {
	ssize_t n = 0;

	if (iface->flags & GR_IFACE_F_UP)
		SAFE_BUF(snprintf, len, "up");
	else
		SAFE_BUF(snprintf, len, "down");
	if (iface->state & GR_IFACE_S_RUNNING)
		SAFE_BUF(snprintf, len, " running");
	if (iface->state & GR_IFACE_S_PROMISC_FIXED)
		SAFE_BUF(snprintf, len, " promisc(fixed)");
	else if (iface->flags & GR_IFACE_F_PROMISC)
		SAFE_BUF(snprintf, len, " promisc");
	if (iface->state & GR_IFACE_S_ALLMULTI)
		SAFE_BUF(snprintf, len, " allmulti");
	if (iface->flags & GR_IFACE_F_PACKET_TRACE)
		SAFE_BUF(snprintf, len, " tracing");
	if (iface->flags & (GR_IFACE_F_SNAT_STATIC | GR_IFACE_F_SNAT_DYNAMIC))
		SAFE_BUF(snprintf, len, " snat");

	return n;
err:
	return -1;
}

uint64_t parse_iface_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	size_t info_size,
	bool update
) {
	const char *name, *promisc;
	uint64_t set_attrs = 0;

	name = arg_str(p, "NAME");
	if (update) {
		struct gr_iface *cur = iface_from_name(c, name);
		if (cur == NULL)
			goto err;
		memcpy(iface, cur, sizeof(*cur) + info_size);
		free(cur);
		name = arg_str(p, "NEW_NAME");
	}

	if (name != NULL) {
		memccpy(iface->name, name, 0, sizeof(iface->name));
		set_attrs |= GR_IFACE_SET_NAME;
	}

	if (arg_str(p, "up")) {
		iface->flags |= GR_IFACE_F_UP;
		set_attrs |= GR_IFACE_SET_FLAGS;
	} else if (arg_str(p, "down")) {
		iface->flags &= ~GR_IFACE_F_UP;
		set_attrs |= GR_IFACE_SET_FLAGS;
	}
	promisc = arg_str(p, "PROMISC");
	if (promisc != NULL && strcmp(promisc, "on") == 0) {
		iface->flags |= GR_IFACE_F_PROMISC;
		set_attrs |= GR_IFACE_SET_FLAGS;
	} else if (promisc != NULL && strcmp(promisc, "off") == 0) {
		iface->flags &= ~GR_IFACE_F_PROMISC;
		set_attrs |= GR_IFACE_SET_FLAGS;
	}

	if (arg_u16(p, "MTU", &iface->mtu) == 0)
		set_attrs |= GR_IFACE_SET_MTU;

	if (arg_str(p, "VRF") != NULL) {
		if (arg_vrf(c, p, "VRF", &iface->vrf_id) < 0)
			goto err;
		set_attrs |= GR_IFACE_SET_VRF;
	} else if (arg_str(p, "DOMAIN") != NULL) {
		if (arg_iface(c, p, "DOMAIN", GR_IFACE_TYPE_UNDEF, &iface->domain_id) < 0)
			goto err;
		set_attrs |= GR_IFACE_SET_DOMAIN;
	}

	name = arg_str(p, "DESCR");
	if (name != NULL) {
		memccpy(iface->description, name, 0, sizeof(iface->description));
		set_attrs |= GR_IFACE_SET_DESCR;
	}

	return set_attrs;
err:
	return 0;
}

static cmd_status_t iface_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_del_req req;

	if (arg_iface(c, p, "NAME", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IFACE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	iface_cache_del(c, req.iface_id);

	return CMD_SUCCESS;
}

static cmd_status_t iface_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_list_req req;
	const struct cli_iface_type *type;
	const struct gr_iface *iface;
	char buf[128];
	size_t n;
	int ret;

	type = type_from_name(arg_str(p, "TYPE"));
	if (type == NULL)
		req.type = GR_IFACE_TYPE_UNDEF;
	else
		req.type = type->type_id;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "NAME", GR_DISP_LEFT); // 0
	gr_table_column(table, "ID", GR_DISP_RIGHT | GR_DISP_INT); // 1
	gr_table_column(table, "FLAGS", GR_DISP_STR_ARRAY); // 2
	gr_table_column(table, "MODE", GR_DISP_LEFT); // 3
	gr_table_column(table, "DOMAIN", GR_DISP_LEFT); // 4
	gr_table_column(table, "TYPE", GR_DISP_LEFT); // 5
	gr_table_column(table, "INFO", GR_DISP_LEFT); // 6

	gr_api_client_stream_foreach (iface, ret, c, GR_IFACE_LIST, sizeof(req), &req) {
		const struct cli_iface_type *type = type_from_id(iface->type);

		iface_cache_update(c, iface);

		// name
		gr_table_cell(table, 0, "%s", iface->name);

		// id
		gr_table_cell(table, 1, "%u", iface->id);

		// flags
		if (iface_flags_format(buf, sizeof(buf), iface) > 0)
			gr_table_cell(table, 2, "%s", buf);

		// mode
		gr_table_cell(table, 3, "%s", gr_iface_mode_name(iface->mode));

		// domain
		if (iface->mode == GR_IFACE_MODE_VRF)
			gr_table_cell(table, 4, "%s", iface_name_from_id(c, iface->vrf_id));
		else
			gr_table_cell(table, 4, "%s", iface_name_from_id(c, iface->domain_id));

		// type
		gr_table_cell(table, 5, "%s", gr_iface_type_name(iface->type));

		// info
		assert(type != NULL);
		buf[0] = 0;
		type->list_info(c, iface, buf, sizeof(buf));
		n = strlen(buf);
		if (n < sizeof(buf) - 1 && iface->description[0] != 0) {
			if (n != 0)
				n += snprintf(buf + n, sizeof(buf) - n, " ");
			if (n < sizeof(buf) - 1)
				n += snprintf(
					buf + n, sizeof(buf) - n, "\"%s\"", iface->description
				);
		}
		if (n >= sizeof(buf) - 1) {
			n = sizeof(buf) - strlen("...") - 1;
			snprintf(buf + n, sizeof(buf) - n, "...");
		}
		gr_table_cell(table, 6, "%s", buf);

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t iface_stats(struct gr_api_client *c, const struct ec_pnode * /*p*/) {
	struct gr_iface_stats_get_resp *resp = NULL;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_IFACE_STATS_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "INTERFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "RX_PACKETS", GR_DISP_RIGHT | GR_DISP_INT); // 1
	gr_table_column(table, "RX_BYTES", GR_DISP_RIGHT | GR_DISP_INT); // 2
	gr_table_column(table, "RX_DROPS", GR_DISP_RIGHT | GR_DISP_INT); // 3
	gr_table_column(table, "TX_PACKETS", GR_DISP_RIGHT | GR_DISP_INT); // 4
	gr_table_column(table, "TX_BYTES", GR_DISP_RIGHT | GR_DISP_INT); // 5
	gr_table_column(table, "TX_ERRORS", GR_DISP_RIGHT | GR_DISP_INT); // 6
	gr_table_column(table, "CP_RX_PACKETS", GR_DISP_RIGHT | GR_DISP_INT); // 7
	gr_table_column(table, "CP_RX_BYTES", GR_DISP_RIGHT | GR_DISP_INT); // 8
	gr_table_column(table, "CP_TX_PACKETS", GR_DISP_RIGHT | GR_DISP_INT); // 9
	gr_table_column(table, "CP_TX_BYTES", GR_DISP_RIGHT | GR_DISP_INT); // 10

	for (uint16_t i = 0; i < resp->n_stats; i++) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, resp->stats[i].iface_id));
		gr_table_cell(table, 1, "%lu", resp->stats[i].rx_packets);
		gr_table_cell(table, 2, "%lu", resp->stats[i].rx_bytes);
		gr_table_cell(table, 3, "%lu", resp->stats[i].rx_drops);
		gr_table_cell(table, 4, "%lu", resp->stats[i].tx_packets);
		gr_table_cell(table, 5, "%lu", resp->stats[i].tx_bytes);
		gr_table_cell(table, 6, "%lu", resp->stats[i].tx_errors);
		gr_table_cell(table, 7, "%lu", resp->stats[i].cp_rx_packets);
		gr_table_cell(table, 8, "%lu", resp->stats[i].cp_rx_bytes);
		gr_table_cell(table, 9, "%lu", resp->stats[i].cp_tx_packets);
		gr_table_cell(table, 10, "%lu", resp->stats[i].cp_tx_bytes);

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t iface_rates(struct gr_api_client *c, const struct ec_pnode * /*p*/) {
	const struct gr_iface_stats_get_resp *resp1, *resp2;
	void *resp1_ptr = NULL, *resp2_ptr = NULL;
	cmd_status_t status = CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IFACE_STATS_GET, 0, NULL, &resp1_ptr) < 0)
		goto end;
	resp1 = resp1_ptr;

	sleep(1);

	if (gr_api_client_send_recv(c, GR_IFACE_STATS_GET, 0, NULL, &resp2_ptr) < 0)
		goto end;
	resp2 = resp2_ptr;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "INTERFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "RX_PACKETS/S", GR_DISP_RIGHT | GR_DISP_INT); // 1
	gr_table_column(table, "RX_BYTES/S", GR_DISP_RIGHT | GR_DISP_INT); // 2
	gr_table_column(table, "RX_DROPS/S", GR_DISP_RIGHT | GR_DISP_INT); // 3
	gr_table_column(table, "TX_PACKETS/S", GR_DISP_RIGHT | GR_DISP_INT); // 4
	gr_table_column(table, "TX_BYTES/S", GR_DISP_RIGHT | GR_DISP_INT); // 5
	gr_table_column(table, "TX_ERRORS/S", GR_DISP_RIGHT | GR_DISP_INT); // 6

	for (uint16_t i = 0; i < resp2->n_stats; i++) {
		const struct gr_iface_stats *s2 = &resp2->stats[i];
		const struct gr_iface_stats *s1 = NULL;

		for (uint16_t j = 0; j < resp1->n_stats; j++) {
			s1 = &resp1->stats[j];
			if (s1->iface_id == s2->iface_id)
				break;
			else
				s1 = NULL;
		}
		if (s1 == NULL)
			continue;

		struct gr_iface *iface = iface_from_id(c, s2->iface_id);
		if (iface != NULL)
			gr_table_cell(table, 0, "%s", iface->name);
		else
			gr_table_cell(table, 0, "%u", s2->iface_id);
		free(iface);

		gr_table_cell(table, 1, "%lu", s2->rx_packets - s1->rx_packets);
		gr_table_cell(table, 2, "%lu", s2->rx_bytes - s1->rx_bytes);
		gr_table_cell(table, 3, "%lu", s2->rx_drops - s1->rx_drops);
		gr_table_cell(table, 4, "%lu", s2->tx_packets - s1->tx_packets);
		gr_table_cell(table, 5, "%lu", s2->tx_bytes - s1->tx_bytes);
		gr_table_cell(table, 6, "%lu", s2->tx_errors - s1->tx_errors);

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);
	status = CMD_SUCCESS;

end:
	free(resp1_ptr);
	free(resp2_ptr);

	return status;
}

static cmd_status_t iface_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct cli_iface_type *type;
	char buf[128];

	if (arg_str(p, "stats") != NULL) {
		return iface_stats(c, p);
	}

	if (arg_str(p, "rates") != NULL) {
		return iface_rates(c, p);
	}

	if (arg_str(p, "NAME") == NULL || arg_str(p, "TYPE") != NULL) {
		return iface_list(c, p);
	}

	struct gr_iface *iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	printf("name: %s\n", iface->name);
	if (iface->description[0] != '\0')
		printf("description: %s\n", iface->description);
	printf("type: %s\n", gr_iface_type_name(iface->type));
	printf("id: %u\n", iface->id);
	if (iface_flags_format(buf, sizeof(buf), iface) < 0) {
		free(iface);
		return CMD_ERROR;
	}
	printf("flags: %s\n", buf);
	printf("mode: %s\n", gr_iface_mode_name(iface->mode));

	if (iface->mode == GR_IFACE_MODE_VRF)
		printf("vrf: %s\n", iface_name_from_id(c, iface->vrf_id));
	else
		printf("domain: %s\n", iface_name_from_id(c, iface->domain_id));

	printf("mtu: %u\n", iface->mtu);

	if (iface->speed == UINT32_MAX)
		printf("speed: unknown\n");
	else
		printf("speed: %u Mb/s\n", iface->speed);

	type = type_from_id(iface->type);
	assert(type != NULL);
	type->show(c, iface);

	free(iface);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	if (INTERFACE_ADD_CTX(root) == NULL)
		return -1;

	if (INTERFACE_SET_CTX(root) == NULL)
		return -1;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root),
		"del NAME",
		iface_del,
		"Delete an existing interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(INTERFACE_CTX(root), "stats", iface_stats, "Show interface counters.");
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root), "rates", iface_rates, "Show interface counter rates."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root),
		"[show] [(name NAME)|(type TYPE)]",
		iface_show,
		"Show interface details.",
		with_help(
			"Show only this interface.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Show only this type of interface.",
			ec_node_dyn("TYPE", complete_iface_types, NULL)
		)
	);
	if (ret < 0)
		return ret;

	return ret;
}

static struct cli_context ctx = {
	.name = "infra iface",
	.init = ctx_init,
};

static void iface_event_print(uint32_t event, const void *obj) {
	const struct gr_iface *iface = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_IFACE_ADD:
		action = "add";
		break;
	case GR_EVENT_IFACE_POST_ADD:
		action = "post add";
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		action = "pre del";
		break;
	case GR_EVENT_IFACE_REMOVE:
		action = "del";
		break;
	case GR_EVENT_IFACE_STATUS_UP:
		action = "up";
		break;
	case GR_EVENT_IFACE_STATUS_DOWN:
		action = "down";
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		action = "reconf";
		break;
	case GR_EVENT_IFACE_MAC_CHANGE:
		action = "mac change";
		break;
	default:
		action = "?";
		break;
	}

	printf("iface %s: %s type=%s id=%u mtu=%u\n",
	       action,
	       iface->name,
	       gr_iface_type_name(iface->type),
	       iface->id,
	       iface->mtu);
}

static struct cli_event_printer printer = {
	.print = iface_event_print,
	.ev_count = 8,
	.ev_types = {
		GR_EVENT_IFACE_ADD,
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
		GR_EVENT_IFACE_POST_RECONFIG,
		GR_EVENT_IFACE_MAC_CHANGE,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
