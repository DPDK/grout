// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "vlan_filtering_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>

#include <rte_malloc.h>

#include <errno.h>
#include <string.h>

struct vlan_filter_stats vlan_filter_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct vlan_filtering *vlan_filtering_alloc(void) {
	struct vlan_filtering *vf;

	vf = rte_zmalloc("vlan_filtering", sizeof(*vf), 0);
	if (vf == NULL)
		return NULL;

	vf->enabled = false;

	for (uint16_t i = 0; i < L2_MAX_IFACES; i++) {
		vf->port_configs[i].mode = PORT_VLAN_MODE_ACCESS;
		vf->port_configs[i].access_vlan = 1;
		vf->port_configs[i].native_vlan = 1;
		vf->port_configs[i].pvid_enabled = true;
		vlan_clear_all(vf->port_configs[i].allowed_vlans);
		vlan_allow(vf->port_configs[i].allowed_vlans, 1);
	}

	return vf;
}

void vlan_filtering_free(struct vlan_filtering *vf) {
	if (vf != NULL)
		rte_free(vf);
}

int vlan_port_set_access(struct vlan_filtering *vf, uint16_t iface_id, uint16_t vlan_id) {
	struct port_vlan_config *cfg;

	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (vlan_id == 0 || vlan_id > MAX_VLAN_ID)
		return -EINVAL;

	cfg = &vf->port_configs[iface_id];
	cfg->mode = PORT_VLAN_MODE_ACCESS;
	cfg->access_vlan = vlan_id;
	cfg->pvid_enabled = true;

	vlan_clear_all(cfg->allowed_vlans);
	vlan_allow(cfg->allowed_vlans, vlan_id);

	return 0;
}

int vlan_port_set_trunk(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t native_vlan,
	const uint16_t *allowed_vlans,
	uint16_t num_vlans
) {
	struct port_vlan_config *cfg;

	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (native_vlan > MAX_VLAN_ID)
		return -EINVAL;

	cfg = &vf->port_configs[iface_id];
	cfg->mode = PORT_VLAN_MODE_TRUNK;
	cfg->native_vlan = native_vlan;
	cfg->pvid_enabled = (native_vlan != 0);

	vlan_clear_all(cfg->allowed_vlans);
	if (num_vlans == 0) {
		vlan_allow_all(cfg->allowed_vlans);
	} else {
		for (uint16_t i = 0; i < num_vlans; i++) {
			if (allowed_vlans[i] > 0 && allowed_vlans[i] <= MAX_VLAN_ID)
				vlan_allow(cfg->allowed_vlans, allowed_vlans[i]);
		}
	}

	if (native_vlan > 0)
		vlan_allow(cfg->allowed_vlans, native_vlan);

	return 0;
}

int vlan_port_set_translation(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t outer_vlan,
	uint16_t inner_vlan
) {
	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (outer_vlan > MAX_VLAN_ID || inner_vlan > MAX_VLAN_ID)
		return -EINVAL;

	struct port_vlan_config *cfg = &vf->port_configs[iface_id];
	cfg->translation.ingress_outer_vlan = outer_vlan;
	cfg->translation.ingress_inner_vlan = inner_vlan;
	cfg->translation.ingress_enabled = true;

	return 0;
}

int vlan_port_clear_translation(struct vlan_filtering *vf, uint16_t iface_id) {
	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;

	vf->port_configs[iface_id].translation.ingress_enabled = false;
	vf->port_configs[iface_id].translation.egress_enabled = false;
	vf->port_configs[iface_id].translation.qinq_enabled = false;

	return 0;
}

int vlan_port_set_egress_translation(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t outer_vlan,
	uint16_t inner_vlan
) {
	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (outer_vlan > MAX_VLAN_ID || inner_vlan > MAX_VLAN_ID)
		return -EINVAL;

	struct port_vlan_config *cfg = &vf->port_configs[iface_id];
	cfg->translation.egress_outer_vlan = outer_vlan;
	cfg->translation.egress_inner_vlan = inner_vlan;
	cfg->translation.egress_enabled = true;

	return 0;
}

int vlan_port_set_qinq(struct vlan_filtering *vf, uint16_t iface_id, uint16_t svid) {
	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (svid > MAX_VLAN_ID)
		return -EINVAL;

	vf->port_configs[iface_id].translation.qinq_svid = svid;
	vf->port_configs[iface_id].translation.qinq_enabled = true;

	return 0;
}

int vlan_port_clear_qinq(struct vlan_filtering *vf, uint16_t iface_id) {
	if (vf == NULL || iface_id >= L2_MAX_IFACES)
		return -EINVAL;

	vf->port_configs[iface_id].translation.qinq_enabled = false;
	return 0;
}

bool vlan_ingress_check(
	const struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t vlan_id,
	bool is_tagged
) {
	const struct port_vlan_config *cfg;

	if (vf == NULL || !vf->enabled || iface_id >= L2_MAX_IFACES)
		return true;

	cfg = &vf->port_configs[iface_id];

	switch (cfg->mode) {
	case PORT_VLAN_MODE_ACCESS:
		if (is_tagged && vlan_id != cfg->access_vlan)
			return false;
		return true;

	case PORT_VLAN_MODE_TRUNK:
		if (!is_tagged)
			return cfg->native_vlan != 0;
		return vlan_is_allowed(cfg->allowed_vlans, vlan_id);

	case PORT_VLAN_MODE_HYBRID:
		if (!is_tagged)
			return cfg->native_vlan != 0;
		return vlan_is_allowed(cfg->allowed_vlans, vlan_id);
	}

	return true;
}

bool vlan_egress_check(
	const struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t vlan_id,
	bool *should_untag
) {
	const struct port_vlan_config *cfg;

	*should_untag = false;

	if (vf == NULL || !vf->enabled || iface_id >= L2_MAX_IFACES)
		return true;

	cfg = &vf->port_configs[iface_id];

	if (!vlan_is_allowed(cfg->allowed_vlans, vlan_id))
		return false;

	switch (cfg->mode) {
	case PORT_VLAN_MODE_ACCESS:
		*should_untag = true;
		break;
	case PORT_VLAN_MODE_TRUNK:
	case PORT_VLAN_MODE_HYBRID:
		*should_untag = (vlan_id == cfg->native_vlan);
		break;
	}

	return true;
}

// Helper: check if iface is a member of the bridge.
static bool bridge_has_member(const struct iface_info_bridge *br, uint16_t iface_id) {
	for (unsigned i = 0; i < br->n_members; i++) {
		if (br->members[i] != NULL && br->members[i]->id == iface_id)
			return true;
	}
	return false;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out vlan_filtering_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_vlan_filtering_req *req = request;
	struct iface *bridge;
	struct iface_info_bridge *br;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);

	if (req->enabled && br->vlan_filter == NULL) {
		br->vlan_filter = vlan_filtering_alloc();
		if (br->vlan_filter == NULL)
			return api_out(ENOMEM, 0, NULL);
	}

	if (br->vlan_filter != NULL) {
		br->vlan_filter->enabled = req->enabled;

		if (!req->enabled) {
			vlan_filtering_free(br->vlan_filter);
			br->vlan_filter = NULL;
		}
	}

	return api_out(0, 0, NULL);
}

static struct api_out vlan_filtering_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_vlan_filtering_req *req = request;
	struct gr_l2_vlan_filtering_status *resp;
	const struct iface *bridge;
	const struct vlan_filtering *vf;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	vf = bridge_get_vlan_filtering(bridge);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->enabled = (vf != NULL) ? vf->enabled : false;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out port_vlan_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_port_vlan_req *req = request;
	const struct iface *bridge;
	const struct iface_info_bridge *br;
	struct vlan_filtering *vf;
	int ret;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);
	vf = br->vlan_filter;
	if (vf == NULL)
		return api_out(ENOENT, 0, NULL);

	if (!bridge_has_member(br, req->iface_id))
		return api_out(EINVAL, 0, NULL);

	switch (req->mode) {
	case GR_PORT_VLAN_MODE_ACCESS:
		ret = vlan_port_set_access(vf, req->iface_id, req->access_vlan);
		break;

	case GR_PORT_VLAN_MODE_TRUNK:
		ret = vlan_port_set_trunk(
			vf, req->iface_id, req->native_vlan,
			req->allowed_vlans, req->num_allowed_vlans
		);
		break;

	case GR_PORT_VLAN_MODE_HYBRID:
		ret = vlan_port_set_trunk(
			vf, req->iface_id, req->native_vlan,
			req->allowed_vlans, req->num_allowed_vlans
		);
		if (ret == 0)
			vf->port_configs[req->iface_id].mode = PORT_VLAN_MODE_HYBRID;
		break;

	default:
		return api_out(EINVAL, 0, NULL);
	}

	if (ret < 0)
		return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out port_vlan_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_port_vlan_req *req = request;
	struct gr_l2_port_vlan_status *resp;
	const struct iface *bridge;
	const struct vlan_filtering *vf;
	const struct port_vlan_config *cfg;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	vf = bridge_get_vlan_filtering(bridge);
	if (vf == NULL || req->iface_id >= L2_MAX_IFACES)
		return api_out(ENOENT, 0, NULL);

	cfg = &vf->port_configs[req->iface_id];

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->iface_id = req->iface_id;
	resp->mode = cfg->mode;
	resp->access_vlan = cfg->access_vlan;
	resp->native_vlan = cfg->native_vlan;
	resp->pvid_enabled = cfg->pvid_enabled;

	resp->num_allowed_vlans = 0;
	for (uint16_t vlan = 1; vlan <= MAX_VLAN_ID && resp->num_allowed_vlans < 256; vlan++) {
		if (vlan_is_allowed(cfg->allowed_vlans, vlan))
			resp->allowed_vlans[resp->num_allowed_vlans++] = vlan;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out vlan_translation_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_vlan_translation_req *req = request;
	const struct iface *bridge;
	struct vlan_filtering *vf;
	int ret;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	vf = iface_info_bridge(bridge)->vlan_filter;
	if (vf == NULL)
		return api_out(ENOENT, 0, NULL);

	if (req->enabled)
		ret = vlan_port_set_translation(vf, req->iface_id, req->outer_vlan, req->inner_vlan);
	else
		ret = vlan_port_clear_translation(vf, req->iface_id);

	if (ret < 0)
		return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out vlan_egress_translation_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_vlan_egress_translation_req *req = request;
	const struct iface *bridge;
	struct vlan_filtering *vf;
	int ret;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	vf = iface_info_bridge(bridge)->vlan_filter;
	if (vf == NULL)
		return api_out(ENOENT, 0, NULL);

	if (req->enabled) {
		ret = vlan_port_set_egress_translation(
			vf, req->iface_id, req->outer_vlan, req->inner_vlan
		);
	} else {
		if (req->iface_id >= L2_MAX_IFACES)
			return api_out(EINVAL, 0, NULL);
		vf->port_configs[req->iface_id].translation.egress_enabled = false;
		ret = 0;
	}

	if (ret < 0)
		return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out vlan_qinq_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_vlan_qinq_req *req = request;
	const struct iface *bridge;
	struct vlan_filtering *vf;
	int ret;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	vf = iface_info_bridge(bridge)->vlan_filter;
	if (vf == NULL)
		return api_out(ENOENT, 0, NULL);

	if (req->enabled)
		ret = vlan_port_set_qinq(vf, req->iface_id, req->svid);
	else
		ret = vlan_port_clear_qinq(vf, req->iface_id);

	if (ret < 0)
		return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out vlan_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_stats_get_req *req = request;
	struct gr_l2_vlan_stats *resp;

	if (req->bridge_id >= L2_MAX_BRIDGES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct vlan_filter_stats *st = &vlan_filter_stats[req->bridge_id][lcore];
		resp->ingress_filtered += st->ingress_filtered;
		resp->egress_filtered += st->egress_filtered;
		resp->pvid_added += st->pvid_added;
		resp->tag_removed += st->tag_removed;
		resp->translated += st->translated;
		resp->egress_translated += st->egress_translated;
		resp->qinq_added += st->qinq_added;
		resp->qinq_removed += st->qinq_removed;
		resp->mode_access += st->mode_access;
		resp->mode_trunk += st->mode_trunk;
		resp->mode_hybrid += st->mode_hybrid;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler vlan_filtering_set_h = {
	.name = "vlan filtering set",
	.request_type = GR_L2_VLAN_FILTERING_SET,
	.callback = vlan_filtering_set_cb,
};
static struct gr_api_handler vlan_filtering_get_h = {
	.name = "vlan filtering get",
	.request_type = GR_L2_VLAN_FILTERING_GET,
	.callback = vlan_filtering_get_cb,
};
static struct gr_api_handler port_vlan_set_h = {
	.name = "port vlan set",
	.request_type = GR_L2_PORT_VLAN_SET,
	.callback = port_vlan_set_cb,
};
static struct gr_api_handler port_vlan_get_h = {
	.name = "port vlan get",
	.request_type = GR_L2_PORT_VLAN_GET,
	.callback = port_vlan_get_cb,
};
static struct gr_api_handler vlan_translation_set_h = {
	.name = "vlan translation set",
	.request_type = GR_L2_VLAN_TRANSLATION_SET,
	.callback = vlan_translation_set_cb,
};
static struct gr_api_handler vlan_egress_translation_set_h = {
	.name = "vlan egress translation set",
	.request_type = GR_L2_VLAN_EGRESS_TRANSLATION_SET,
	.callback = vlan_egress_translation_set_cb,
};
static struct gr_api_handler vlan_qinq_set_h = {
	.name = "vlan qinq set",
	.request_type = GR_L2_VLAN_QINQ_SET,
	.callback = vlan_qinq_set_cb,
};
static struct gr_api_handler vlan_stats_get_h = {
	.name = "vlan stats get",
	.request_type = GR_L2_VLAN_STATS_GET,
	.callback = vlan_stats_get_cb,
};

RTE_INIT(vlan_filtering_constructor) {
	gr_register_api_handler(&vlan_filtering_set_h);
	gr_register_api_handler(&vlan_filtering_get_h);
	gr_register_api_handler(&port_vlan_set_h);
	gr_register_api_handler(&port_vlan_get_h);
	gr_register_api_handler(&vlan_translation_set_h);
	gr_register_api_handler(&vlan_egress_translation_set_h);
	gr_register_api_handler(&vlan_qinq_set_h);
	gr_register_api_handler(&vlan_stats_get_h);
}
