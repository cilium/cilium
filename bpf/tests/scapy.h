/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "../lib/hexdump.h"

#define SCAPY_BUF(NAME) __scapy_buf_##NAME

#define __SCAPY_BUF_BYTES(NAME) __SCAPY_BUF_##NAME##_BYTES

#define SCAPY_DEF_BUF(NAME, ...) \
	const __u8 SCAPY_BUF(NAME)[] = __SCAPY_BUF_BYTES(NAME)

#define SCAPY_PKT_BUILDER(BUILDER, NAME)				       \
	do {								       \
		if (!pktgen__push_data(&(BUILDER), (void *) &SCAPY_BUF(NAME),  \
				      sizeof(SCAPY_BUF(NAME))))		       \
			return TEST_ERROR;				       \
	} while (0)

#define SCAPY_ASSERT_PKT_BUF_OFF(NAME, CTX, OFF, BUF_NAME, LEN)				\
	do {										\
		void *__data = (void *)(long)ctx->data;					\
		void *__data_end = (void *)(long)ctx->data_end;				\
		__data += OFF;								\
		if (__data + (LEN) > __data_end) {					\
			test_log("CTX size - offset < LEN " __FILE__ ":" LINE_STRING);	\
			test_fail_now();						\
		}									\
		if (sizeof(SCAPY_BUF(BUF_NAME)) < (LEN) ) {				\
			test_log("BUF size < LEN " __FILE__ ":" LINE_STRING); 		\
			test_fail_now();						\
		}									\
		if (memcmp(__data, & SCAPY_BUF(BUF_NAME), LEN) != 0) {			\
			test_log("CTX and buffer '" #BUF_NAME "' mismatch " __FILE__ ":" LINE_STRING);									\
			hexdump_len_off(__FILE__ ":" LINE_STRING " assert '" NAME "' FAILED! Got (ctx)", ctx, LEN, OFF); 						\
			scapy_hexdump(__FILE__ ":" LINE_STRING " assert '" NAME "' FAILED! Expected (buf)", & SCAPY_BUF(BUF_NAME)[0], sizeof(SCAPY_BUF(BUF_NAME))); 	\
			test_fail_now();																\
		}																			\
	} while (0)

#define SCAPY_ASSERT_PKT_BUF(CTX, BUF_NAME, LEN) \
	SCAPY_ASSERT_PKT_BUF_OFF(CTX, 0, BUF_NAME, LEN)

static __always_inline
void scapy_hexdump(const char *msg, const unsigned char *scapy_buf,
		   const __u16 len)
{
	int i;
	char buf[HD_MAX_BYTES * 2 + 1] = {0};
	char *b;

	if (len > HD_MAX_BYTES) {
		hex_printk("%s: pkt[%s]", msg, "ERROR: len too big!");
		return;
	}

	for (i = 0; i < len; ++i) {
		b = (char *)&scapy_buf[i];
		buf[i * 2]     = __hexdump_nibble_to_char((*b & 0xF0) >> 4);
		buf[i * 2 + 1] = __hexdump_nibble_to_char((*b & 0x0F));
	}

	buf[2 * i] = '\0';
	hex_printk("%s: pkt[%s]", msg, buf);
}

#include "scapy/.pkts.h"
