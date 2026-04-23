// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include <gr_capture.h>

#include <stdint.h>
#include <stdio.h>

// pcapng file writer.
//
// We write pcapng (not legacy pcap) because it supports per-interface
// metadata via Interface Description Blocks (IDB). This is needed for
// multi-interface captures where each packet carries the originating
// interface id. Legacy pcap only supports a single link type and has
// no concept of multiple interfaces.
//
// There is no standalone C library for writing pcapng. libpcap can
// read pcapng but only writes legacy pcap via pcap_dump(). DPDK has
// librte_pcapng but it operates on rte_mbuf, not raw byte buffers.
// The format is simple enough (SHB + IDB + EPB with 4-byte padding)
// that a minimal writer is preferable to pulling in a large dependency.
//
// Reference: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html

// Write a Section Header Block.
int pcapng_write_shb(FILE *f);

// Write an Interface Description Block.
int pcapng_write_idb(FILE *f, const struct gr_capture_iface *iface, uint32_t snap_len);

// Write an Enhanced Packet Block.
int pcapng_write_epb(
	FILE *f,
	uint32_t iface_idx,
	uint64_t timestamp_ns,
	uint32_t cap_len,
	uint32_t pkt_len,
	const uint8_t *data,
	uint8_t direction
);
