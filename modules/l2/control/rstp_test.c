// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "rstp_priv.h"

#include <gr_cmocka.h>
#include <gr_event.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vrf.h>

#include <stdlib.h>
#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
void gr_register_module(struct gr_module *) { }
void iface_type_register(const struct iface_type *) { }
void gr_event_push(uint32_t, const void *) { }
void gr_event_subscribe(struct gr_event_subscription *) { }
uint16_t vrf_default_get_or_create(void) { return 0; }
int vrf_incref(uint16_t) { return 0; }
void fdb_purge_iface(uint16_t) { }
void fdb_purge_bridge(uint16_t) { }
// VLAN filtering stubs needed by bridge.c.
#include "vlan_filtering_priv.h"
void vlan_filtering_free(struct vlan_filtering *vf) { (void)vf; }
// Multicast snooping stubs needed by bridge.c.
#include "mcast_snooping_priv.h"
void mcast_snooping_free(struct mcast_snooping *m) { (void)m; }
int iface_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	(void)iface; (void)mac; return 0;
}
int iface_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	(void)iface;
	memset(mac, 0, sizeof(*mac));
	mac->addr_bytes[0] = 0x02;
	return 0;
}
struct iface *iface_from_id(uint16_t id) { (void)id; return NULL; }

// DPDK wraps for rstp.c.
void *__wrap_rte_zmalloc(const char *type, size_t size, unsigned align) {
	(void)type; (void)align;
	return calloc(1, size);
}
void __wrap_rte_free(void *ptr) { free(ptr); }

static void test_path_cost(void **state) {
	(void)state;
	assert_int_equal(rstp_calc_path_cost(10), RSTP_PATH_COST_10M);
	assert_int_equal(rstp_calc_path_cost(100), RSTP_PATH_COST_100M);
	assert_int_equal(rstp_calc_path_cost(1000), RSTP_PATH_COST_1G);
	assert_int_equal(rstp_calc_path_cost(10000), RSTP_PATH_COST_10G);
	assert_int_equal(rstp_calc_path_cost(100000), RSTP_PATH_COST_100G);
}

static void test_bridge_alloc_free(void **state) {
	(void)state;
	struct rstp_bridge *rstp = rstp_bridge_alloc(NULL, 32768);
	assert_non_null(rstp);
	assert_false(rstp->enabled);
	assert_int_equal(rstp->hello_time, RSTP_DEFAULT_HELLO_TIME);
	assert_int_equal(rstp->forward_delay, RSTP_DEFAULT_FORWARD_DELAY);
	assert_int_equal(rstp->max_age, RSTP_DEFAULT_MAX_AGE);
	assert_int_equal(rstp->root_bridge_id, rstp->bridge_identifier);
	rstp_bridge_free(rstp);
}

static void test_port_add_del(void **state) {
	(void)state;
	struct rstp_bridge *rstp = rstp_bridge_alloc(NULL, 32768);
	assert_non_null(rstp);

	assert_int_equal(rstp_port_add(rstp, 100), 0);
	assert_int_equal(gr_vec_len(rstp->ports), 1);
	assert_int_equal(rstp->ports[0].iface_id, 100);
	assert_int_equal(rstp->ports[0].priority, 128);

	assert_int_equal(rstp_port_add(rstp, 101), 0);
	assert_int_equal(gr_vec_len(rstp->ports), 2);

	// Duplicate.
	assert_int_equal(rstp_port_add(rstp, 100), -EEXIST);

	assert_int_equal(rstp_port_del(rstp, 100), 0);
	assert_int_equal(gr_vec_len(rstp->ports), 1);
	assert_int_equal(rstp->ports[0].iface_id, 101);

	assert_int_equal(rstp_port_del(rstp, 999), -ENOENT);

	rstp_bridge_free(rstp);
}

static void test_state_machine(void **state) {
	(void)state;
	struct rstp_bridge *rstp = rstp_bridge_alloc(NULL, 32768);
	assert_non_null(rstp);
	rstp->enabled = true;

	rstp_port_add(rstp, 100);
	struct rstp_port *port = &rstp->ports[0];

	// Initially disabled.
	assert_int_equal(port->state, RSTP_STATE_DISABLED);

	// Assign designated role and activate.
	port->role = RSTP_ROLE_DESIGNATED;
	port->state = RSTP_STATE_DISCARDING;

	rstp_port_state_machine(rstp, port);
	assert_int_equal(port->state, RSTP_STATE_LEARNING);

	// Expire forward delay timer.
	port->fd_when = 0;
	rstp_port_state_machine(rstp, port);
	assert_int_equal(port->state, RSTP_STATE_FORWARDING);

	// Edge port skips to forwarding.
	port->oper_edge = true;
	port->state = RSTP_STATE_DISCARDING;
	rstp_port_state_machine(rstp, port);
	assert_int_equal(port->state, RSTP_STATE_FORWARDING);

	// Alternate ports stay in discarding.
	port->oper_edge = false;
	port->role = RSTP_ROLE_ALTERNATE;
	rstp_port_state_machine(rstp, port);
	assert_int_equal(port->state, RSTP_STATE_DISCARDING);

	rstp_bridge_free(rstp);
}

static void test_role_selection(void **state) {
	(void)state;
	struct rstp_bridge *rstp = rstp_bridge_alloc(NULL, 32768);
	assert_non_null(rstp);
	rstp->enabled = true;

	rstp_port_add(rstp, 100);
	rstp_port_add(rstp, 101);

	rstp->ports[0].state = RSTP_STATE_DISCARDING;
	rstp->ports[1].state = RSTP_STATE_DISCARDING;

	// Simulate superior BPDU on port 0.
	rstp->ports[0].msg_priority.root_bridge_id = 0x7000000000000001ULL;
	rstp->ports[0].msg_priority.root_path_cost = 100;
	rstp->ports[0].msg_priority.designated_bridge_id = 0x7000000000000001ULL;
	rstp->ports[0].msg_priority.designated_port_id = 0x8001;

	rstp_update_roles_selection(rstp);

	assert_int_equal(rstp->ports[0].role, RSTP_ROLE_ROOT);
	assert_int_equal(rstp->root_bridge_id, 0x7000000000000001ULL);

	rstp_bridge_free(rstp);
}

static void test_bpdu_guard(void **state) {
	(void)state;
	struct rstp_bridge *rstp = rstp_bridge_alloc(NULL, 32768);
	assert_non_null(rstp);
	rstp->enabled = true;

	rstp_port_add(rstp, 100);
	struct rstp_port *port = &rstp->ports[0];

	port->bpdu_guard = true;
	port->oper_edge = true;
	port->state = RSTP_STATE_FORWARDING;
	port->role = RSTP_ROLE_DESIGNATED;

	struct rstp_bpdu bpdu = {
		.protocol_id = rte_cpu_to_be_16(RSTP_PROTOCOL_ID),
		.protocol_version = RSTP_PROTOCOL_VERSION_RSTP,
		.bpdu_type = RSTP_BPDU_TYPE,
	};

	int ret = rstp_rx_bpdu(rstp, port, &bpdu);
	assert_int_equal(ret, -EPERM);
	assert_int_equal(port->state, RSTP_STATE_DISABLED);
	assert_true(port->bpdu_guard_err > 0);

	rstp_bridge_free(rstp);
}

static void test_datapath_helpers(void **state) {
	(void)state;

	// No RSTP → allow everything.
	assert_true(rstp_port_is_forwarding(NULL, 0));
	assert_true(rstp_port_is_learning(NULL, 0));

	// rstp_get_port_state with NULL → FORWARDING.
	assert_int_equal(rstp_get_port_state(NULL, 0), RSTP_STATE_FORWARDING);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_path_cost),
		cmocka_unit_test(test_bridge_alloc_free),
		cmocka_unit_test(test_port_add_del),
		cmocka_unit_test(test_state_machine),
		cmocka_unit_test(test_role_selection),
		cmocka_unit_test(test_bpdu_guard),
		cmocka_unit_test(test_datapath_helpers),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
