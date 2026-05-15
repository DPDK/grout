// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include "pcapng.h"

#include <gr_errno.h>
#include <gr_string.h>

#include <net/if.h>
#include <string.h>

#define PCAPNG_BT_SHB 0x0A0D0D0A
#define PCAPNG_BT_IDB 0x00000001
#define PCAPNG_BT_EPB 0x00000006

#define PCAPNG_OPT_IF_NAME 2
#define PCAPNG_OPT_IF_TSRESOL 9
#define PCAPNG_EPB_FLAGS 2

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

// pcapng IDBs use LINKTYPE values (not DLT). For Ethernet they
// happen to be the same (1), but for raw IP DLT_RAW=14 while
// LINKTYPE_RAW=101.
#define PCAPNG_LINKTYPE_EN10MB 1
#define PCAPNG_LINKTYPE_RAW 101

static uint16_t iface_type_to_linktype(gr_iface_type_t type) {
	switch (type) {
	case GR_IFACE_TYPE_VRF:
	case GR_IFACE_TYPE_IPIP:
		return PCAPNG_LINKTYPE_RAW;
	default:
		return PCAPNG_LINKTYPE_EN10MB;
	}
}

static int wr(FILE *f, const void *buf, size_t len) {
	if (len == 0)
		return 0;
	if (fwrite(buf, len, 1, f) != 1)
		return errno_set(EIO);
	return 0;
}

int pcapng_write_shb(FILE *f) {
	struct {
		uint32_t type, length;
		uint32_t bom;
		uint16_t major, minor;
		int64_t section_len;
		uint32_t length2;
	} __attribute__((packed)) shb = {
		.type = PCAPNG_BT_SHB,
		.bom = PCAPNG_BYTE_ORDER_MAGIC,
		.major = 1,
		.section_len = -1,
	};
	shb.length = sizeof(shb);
	shb.length2 = sizeof(shb);
	return wr(f, &shb, sizeof(shb));
}

int pcapng_write_idb(FILE *f, const struct gr_capture_iface *iface, uint32_t snap_len) {
	struct __attribute__((packed)) {
		// IDB header
		uint32_t type, length;
		uint16_t link_type, reserved;
		uint32_t snap_len;
		// if_name option (IFNAMSIZ=16 is already 4-byte aligned)
		uint16_t name_type, name_len;
		char name[IFNAMSIZ];
		// if_tsresol option (1 byte padded to 4)
		uint16_t tsresol_type, tsresol_len;
		uint8_t tsresol;
		uint8_t _pad[3];
		// opt_endofopt
		uint32_t opt_end;
		// trailing block length
		uint32_t length2;
	} idb = {
		.type = PCAPNG_BT_IDB,
		.link_type = iface_type_to_linktype(iface->type),
		.snap_len = snap_len,
		.name_type = PCAPNG_OPT_IF_NAME,
		.tsresol_type = PCAPNG_OPT_IF_TSRESOL,
		.tsresol_len = 1,
		.tsresol = 9,
	};
	idb.name_len = strlen(iface->name);
	gr_strcpy(idb.name, sizeof(idb.name), iface->name);
	idb.length = sizeof(idb);
	idb.length2 = sizeof(idb);
	return wr(f, &idb, sizeof(idb));
}

int pcapng_write_epb(
	FILE *f,
	uint32_t iface_idx,
	uint64_t timestamp_ns,
	uint32_t cap_len,
	uint32_t pkt_len,
	const uint8_t *data,
	uint8_t direction
) {
	uint32_t data_padded = (cap_len + 3) & ~3u;

	struct __attribute__((packed)) {
		uint32_t type, length;
		uint32_t iface_id;
		uint32_t ts_hi, ts_lo;
		uint32_t cap_len, orig_len;
	} hdr = {
		.type = PCAPNG_BT_EPB,
		.iface_id = iface_idx,
		.ts_hi = (uint32_t)(timestamp_ns >> 32),
		.ts_lo = (uint32_t)timestamp_ns,
		.cap_len = cap_len,
		.orig_len = pkt_len,
	};

	struct __attribute__((packed)) {
		uint16_t flags_type, flags_len;
		uint32_t flags_val;
		uint32_t opt_end;
		uint32_t length2;
	} tail = {
		.flags_type = PCAPNG_EPB_FLAGS,
		.flags_len = 4,
		.flags_val = direction & 0x3,
	};

	hdr.length = sizeof(hdr) + data_padded + sizeof(tail);
	tail.length2 = hdr.length;

	if (wr(f, &hdr, sizeof(hdr)) < 0)
		return -1;
	if (wr(f, data, cap_len) < 0)
		return -1;
	uint8_t zero[4] = {0};
	if (wr(f, zero, data_padded - cap_len) < 0)
		return -1;
	return wr(f, &tail, sizeof(tail));
}
