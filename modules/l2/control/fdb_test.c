// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#include "_cmocka.h"
#include "clock.h"
#include "config.h"
#include "event.h"
#include "iface.h"
#include "l2.h"
#include "log.h"
#include "module.h"
#include "rcu.h"

#include <rte_eal.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct gr_config gr_config;
__thread gr_clock_ns_t clock_snapshot_ns;
__thread gr_wallclock_ns_t wallclock_snapshot_ns;
__thread bool clock_trusted;
_Atomic gr_clock_ns_t clock_wallclock_offset;

static struct module *fdb_module;
static struct rte_rcu_qsbr *test_rcu;
static cpu_set_t reader_affinity;
static pthread_barrier_t lookup_barrier;
static atomic_bool first_inserted;
static atomic_uint add_events;
static atomic_uint del_events;
static bool force_duplicate;
static bool force_api_race;
static bool signal_delete;
static bool poison_retired;
static atomic_bool reader_ready;
static atomic_bool release_reader;
static atomic_bool delete_started;
static atomic_bool reader_finished;
static bool signal_count;
static struct fdb_entry *retired_entry;
static struct event_base *test_base;
static api_handler_func add_handler, del_handler, flush_handler, config_handler;
static event_sub_cb_t remove_handler;
static struct iface *test_bridge;
static struct iface test_port = {.id = 43, .type = GR_IFACE_TYPE_PORT, .domain_id = 42};
static _Thread_local int reader_slot = -1;
static _Thread_local bool first_lookup;
static const struct rte_ether_addr test_mac = {{0x02, 0, 0, 0, 0, 0x42}};

int __real_rte_hash_lookup_data(const struct rte_hash *, const void *, void **);
int __wrap_rte_hash_lookup_data(const struct rte_hash *, const void *, void **);
int __real_rte_hash_add_key_data(const struct rte_hash *, const void *, void *);
int __wrap_rte_hash_add_key_data(const struct rte_hash *, const void *, void *);
int32_t __real_rte_hash_del_key(const struct rte_hash *, const void *);
int32_t __wrap_rte_hash_del_key(const struct rte_hash *, const void *);
int32_t __real_rte_hash_count(const struct rte_hash *);
int32_t __wrap_rte_hash_count(const struct rte_hash *);

void __api_handler(uint32_t type, api_handler_func callback, const char *, size_t) {
	if (type == GR_FDB_ADD)
		add_handler = callback;
	if (type == GR_FDB_DEL)
		del_handler = callback;
	if (type == GR_FDB_FLUSH)
		flush_handler = callback;
	if (type == GR_FDB_CONFIG_SET)
		config_handler = callback;
}
void api_send(struct api_ctx *, uint32_t, const void *) { }
void event_subscribe(uint32_t type, event_sub_cb_t callback) {
	if (type == GR_EVENT_IFACE_REMOVE)
		remove_handler = callback;
}
void __event_serializer(uint32_t, event_serializer_cb_t, size_t) { }
void module_register(struct module *mod) {
	fdb_module = mod;
}
struct rte_rcu_qsbr *gr_datapath_rcu(void) {
	return test_rcu;
}
struct iface *iface_from_id(uint16_t id) {
	return id == 42 ? test_bridge : id == 43 ? &test_port : NULL;
}
int iface_add_eth_addr(struct iface *, const struct rte_ether_addr *) {
	return 0;
}
int iface_del_eth_addr(struct iface *, const struct rte_ether_addr *) {
	return 0;
}
void event_push(uint32_t event, const void *obj) {
	if (event == GR_EVENT_FDB_ADD)
		atomic_fetch_add(&add_events, 1);
	if (event == GR_EVENT_FDB_DEL) {
		atomic_fetch_add(&del_events, 1);
		if (poison_retired) {
			retired_entry = (struct fdb_entry *)obj;
			retired_entry->prev_iface_id = 43;
		}
	}
}

int __wrap_rte_hash_lookup_data(const struct rte_hash *h, const void *key, void **data) {
	int ret = __real_rte_hash_lookup_data(h, key, data);

	if (force_api_race && reader_slot >= 0 && !first_lookup) {
		assert(ret == -ENOENT);
		first_lookup = true;
		atomic_store(&reader_ready, true);
		while (!atomic_load(&release_reader))
			rte_pause();
	}
	if (force_duplicate && reader_slot >= 0 && !first_lookup) {
		assert(ret == -ENOENT);
		first_lookup = true;
		pthread_barrier_wait(&lookup_barrier);
		// Both readers observed a miss. Delay the second stale result until
		// the first real insert finishes, forcing the overwrite path on the
		// unfixed implementation without replacing any DPDK operation.
		if (reader_slot == 1)
			while (!atomic_load(&first_inserted))
				rte_pause();
	}
	return ret;
}

int32_t __wrap_rte_hash_del_key(const struct rte_hash *h, const void *key) {
	if (signal_delete)
		atomic_store(&delete_started, true);
	return __real_rte_hash_del_key(h, key);
}

int32_t __wrap_rte_hash_count(const struct rte_hash *h) {
	int32_t ret = __real_rte_hash_count(h);

	if (signal_count) {
		signal_count = false;
		assert(ret == 0);
		atomic_store(&delete_started, true);
		while (!atomic_load(&reader_finished))
			rte_pause();
	}
	return ret;
}

int __wrap_rte_hash_add_key_data(const struct rte_hash *h, const void *key, void *data) {
	int ret = __real_rte_hash_add_key_data(h, key, data);

	if (force_duplicate && reader_slot == 0 && ret == 0)
		atomic_store(&first_inserted, true);
	return ret;
}

static void *learn_reader(void *arg) {
	const struct l3_addr local = {0};

	assert(sched_setaffinity(0, sizeof(reader_affinity), &reader_affinity) == 0);
	reader_slot = (intptr_t)arg;
	first_lookup = false;
	assert(rte_thread_register() == 0);
	unsigned id = rte_lcore_id();
	assert(rte_rcu_qsbr_thread_register(test_rcu, id) == 0);
	rte_rcu_qsbr_thread_online(test_rcu, id);
	fdb_learn(42, 43, &test_mac, 0, &local);
	rte_rcu_qsbr_quiescent(test_rcu, id);
	rte_rcu_qsbr_thread_offline(test_rcu, id);
	assert(rte_rcu_qsbr_thread_unregister(test_rcu, id) == 0);
	rte_thread_unregister();
	atomic_store(&reader_finished, true);
	return NULL;
}

static void duplicate_learning_does_not_wait_for_itself(void **) {
	pthread_t readers[2];

	atomic_store(&first_inserted, false);
	atomic_store(&add_events, 0);
	atomic_store(&del_events, 0);
	force_duplicate = true;
	assert_int_equal(pthread_barrier_init(&lookup_barrier, NULL, 2), 0);
	// A real QSBR self-deadlock must fail in bounded time, not hang CI.
	alarm(5);
	assert_int_equal(pthread_create(&readers[0], NULL, learn_reader, (void *)0), 0);
	assert_int_equal(pthread_create(&readers[1], NULL, learn_reader, (void *)1), 0);
	assert_int_equal(pthread_join(readers[0], NULL), 0);
	assert_int_equal(pthread_join(readers[1], NULL), 0);
	alarm(0);
	force_duplicate = false;
	assert_int_equal(pthread_barrier_destroy(&lookup_barrier), 0);
	assert_non_null(fdb_lookup(42, &test_mac, 0));
	assert_int_equal(atomic_load(&add_events), 1);
	assert_int_equal(atomic_load(&del_events), 0);
	fdb_purge_iface(43);
	assert_null(fdb_lookup(42, &test_mac, 0));
	assert_int_equal(atomic_load(&del_events), 1);
}

static void api_insert_wins_over_a_stale_learning_miss(void **) {
	struct gr_fdb_add_req req = {
		.fdb = {
			.iface_id = 43,
			.mac = test_mac,
			.flags = GR_FDB_F_STATIC,
		}
	};
	pthread_t reader;

	force_api_race = true;
	atomic_store(&reader_ready, false);
	atomic_store(&release_reader, false);
	atomic_store(&add_events, 0);
	atomic_store(&del_events, 0);
	alarm(5);
	assert_int_equal(pthread_create(&reader, NULL, learn_reader, (void *)0), 0);
	while (!atomic_load(&reader_ready))
		rte_pause();
	assert_int_equal(add_handler(&req, NULL).status, 0);
	atomic_store(&release_reader, true);
	assert_int_equal(pthread_join(reader, NULL), 0);
	alarm(0);
	force_api_race = false;
	assert_int_equal(fdb_lookup(42, &test_mac, 0)->flags, GR_FDB_F_STATIC);
	assert_int_equal(atomic_load(&add_events), 1);
	assert_int_equal(atomic_load(&del_events), 0);
	fdb_purge_iface(43);
}

static void *learn_while_control_waits(void *) {
	struct rte_ether_addr mac = test_mac;
	const struct l3_addr local = {0};

	assert(sched_setaffinity(0, sizeof(reader_affinity), &reader_affinity) == 0);
	mac.addr_bytes[5]++;
	assert(rte_thread_register() == 0);
	unsigned id = rte_lcore_id();
	assert(rte_rcu_qsbr_thread_register(test_rcu, id) == 0);
	rte_rcu_qsbr_thread_online(test_rcu, id);
	atomic_store(&reader_ready, true);
	while (!atomic_load(&delete_started))
		rte_pause();
	// The control writer holds the FDB lock while waiting for this reader.
	// A blocking reader-side lock would prevent the grace period forever.
	fdb_learn(42, 43, &mac, 0, &local);
	rte_rcu_qsbr_quiescent(test_rcu, id);
	rte_rcu_qsbr_thread_offline(test_rcu, id);
	assert(rte_rcu_qsbr_thread_unregister(test_rcu, id) == 0);
	rte_thread_unregister();
	atomic_store(&reader_finished, true);
	return NULL;
}

enum delete_kind {
	PURGE,
	API_DELETE,
	API_FLUSH,
	IFACE_REMOVE,
	AGE
};

static void control_delete_race(enum delete_kind kind) {
	struct gr_fdb_flush_req flush = {.bridge_id = 42, .iface_id = 43};
	struct gr_fdb_del_req del = {.bridge_id = 42, .mac = test_mac};
	struct rte_ether_addr other = test_mac;
	const struct l3_addr local = {0};
	pthread_t reader;

	other.addr_bytes[5]++;
	fdb_learn(42, 43, &test_mac, 0, &local);
	assert_non_null(fdb_lookup(42, &test_mac, 0));
	if (kind == AGE)
		((struct fdb_entry *)fdb_lookup(42, &test_mac, 0))->last_seen = 0;
	atomic_store(&reader_ready, false);
	atomic_store(&delete_started, false);
	atomic_store(&reader_finished, false);
	signal_delete = true;
	alarm(5);
	assert_int_equal(pthread_create(&reader, NULL, learn_while_control_waits, NULL), 0);
	while (!atomic_load(&reader_ready))
		rte_pause();
	switch (kind) {
	case PURGE:
		fdb_purge_iface(43);
		break;
	case API_DELETE:
		assert_int_equal(del_handler(&del, NULL).status, 0);
		break;
	case API_FLUSH:
		assert_int_equal(flush_handler(&flush, NULL).status, 0);
		break;
	case IFACE_REMOVE:
		remove_handler(GR_EVENT_IFACE_REMOVE, &test_port);
		break;
	case AGE:
		assert_int_equal(event_base_loop(test_base, EVLOOP_ONCE), 0);
		break;
	}
	assert_int_equal(pthread_join(reader, NULL), 0);
	alarm(0);
	signal_delete = false;
	assert_null(fdb_lookup(42, &test_mac, 0));
	assert_null(fdb_lookup(42, &other, 0));
}

static void control_writers_never_block_online_learners(void **) {
	for (enum delete_kind kind = PURGE; kind <= AGE; kind++)
		control_delete_race(kind);
}

static void pool_exhaustion_releases_the_writer_lock(void **) {
	struct rte_mempool *pool = rte_mempool_lookup("fdb-1024");
	const struct l3_addr local = {0};
	unsigned count = 0;
	void *held[1024];

	assert_non_null(pool);
	while (count < ARRAY_DIM(held) && rte_mempool_get(pool, &held[count]) == 0)
		count++;
	assert_int_equal(count, ARRAY_DIM(held));
	fdb_learn(42, 43, &test_mac, 0, &local);
	assert_null(fdb_lookup(42, &test_mac, 0));
	rte_mempool_put_bulk(pool, held, count);
	fdb_learn(42, 43, &test_mac, 0, &local);
	assert_non_null(fdb_lookup(42, &test_mac, 0));
	fdb_purge_iface(43);
}

static void purge_does_not_modify_a_reclaimed_entry(void **) {
	const struct l3_addr local = {0};

	fdb_learn(42, 43, &test_mac, 0, &local);
	retired_entry = NULL;
	poison_retired = true;
	fdb_purge_iface(43);
	poison_retired = false;
	assert_non_null(retired_entry);
	// The backing pool is still allocated, and no allocation has reused its
	// retired object. Detect a post-delete write without fake QSBR/free calls.
	assert_int_equal(retired_entry->prev_iface_id, 43);
}

static void configuration_validation_and_swap_are_serialized(void **) {
	struct gr_fdb_config_set_req req = {.max_entries = 2048};
	struct rte_ether_addr other = test_mac;
	pthread_t reader;

	other.addr_bytes[5]++;
	atomic_store(&reader_ready, false);
	atomic_store(&reader_finished, false);
	atomic_store(&delete_started, false);
	atomic_store(&add_events, 0);
	signal_count = true;
	alarm(5);
	assert_int_equal(pthread_create(&reader, NULL, learn_while_control_waits, NULL), 0);
	while (!atomic_load(&reader_ready))
		rte_pause();
	assert_int_equal(config_handler(&req, NULL).status, 0);
	assert_int_equal(pthread_join(reader, NULL), 0);
	alarm(0);
	// A learner must not successfully insert after the empty check and then
	// have its new entry silently discarded by the configuration swap.
	assert_int_equal(atomic_load(&add_events), 0);
	assert_null(fdb_lookup(42, &other, 0));
	req.max_entries = 1024;
	assert_int_equal(config_handler(&req, NULL).status, 0);
}

int main(void) {
	cpu_set_t allowed;
	char lcores[64];

	assert(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
	reader_affinity = allowed;
	int cpu = 0;
	while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed))
		cpu++;
	assert(cpu < CPU_SETSIZE);
	snprintf(lcores, sizeof(lcores), "0@%d", cpu);
	char *args[] = {
		"fdb_test",
		"--lcores",
		lcores,
		"--no-huge",
		"--no-shconf",
		"--no-pci",
		"--no-telemetry",
		"-m",
		"128",
		NULL
	};
	assert(rte_eal_init(ARRAY_DIM(args) - 1, args) >= 0);
	test_rcu = rte_zmalloc(NULL, rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE), RTE_CACHE_LINE_SIZE);
	assert(test_rcu != NULL);
	assert(rte_rcu_qsbr_init(test_rcu, RTE_MAX_LCORE) == 0);
	test_bridge = rte_zmalloc(
		NULL, sizeof(*test_bridge) + sizeof(struct iface_info_bridge), RTE_CACHE_LINE_SIZE
	);
	assert(test_bridge != NULL);
	test_bridge->id = 42;
	test_bridge->type = GR_IFACE_TYPE_BRIDGE;
	gr_config.max_fdb_entries = 1024;
	test_base = event_base_new();
	assert(test_base != NULL && fdb_module != NULL);
	iface_info_bridge(test_bridge)->ageing_time = 1;
	fdb_module->init(test_base);
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(duplicate_learning_does_not_wait_for_itself),
		cmocka_unit_test(api_insert_wins_over_a_stale_learning_miss),
		cmocka_unit_test(control_writers_never_block_online_learners),
		cmocka_unit_test(pool_exhaustion_releases_the_writer_lock),
		cmocka_unit_test(purge_does_not_modify_a_reclaimed_entry),
		cmocka_unit_test(configuration_validation_and_swap_are_serialized),
	};
	int ret = cmocka_run_group_tests(tests, NULL, NULL);
	fdb_module->fini(test_base);
	event_base_free(test_base);
	rte_free(test_bridge);
	rte_free(test_rcu);
	rte_eal_cleanup();
	return ret;
}
