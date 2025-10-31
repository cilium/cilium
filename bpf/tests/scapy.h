/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "../lib/hexdump.h"

/**
 * Get the reference to the buffer (byte array) with 'NAME'
 */
#define BUF(NAME) __scapy_buf_##NAME

#define __SCAPY_BUF_BYTES(NAME) __SCAPY_BUF_##NAME##_BYTES

/**
 * Declare scapy buffer in stack.
 *
 * NAME: name of the buffer. Unique name in the scope. Use BUF(NAME) to refer
 *       to this buffer.
 *
 * Variable args:
 *  #1: scapy object (layer)
 */
#define BUF_DECL(NAME, ...) \
	const __u8 BUF(NAME)[] = __SCAPY_BUF_BYTES(NAME)

/**
 * Push (append) BUF(NAME) to the end of the ctx pkt builder.
 */
#define BUILDER_PUSH_BUF(BUILDER, NAME)					\
	do {								\
		if (!pktgen__push_data(&(BUILDER), (void *)&BUF(NAME),	\
				       sizeof(BUF(NAME))))		\
			return TEST_ERROR;				\
	} while (0)

/**
 * Compare a packet (ctx) to a scapy buffer starting from ctx's OFF byte
 */
#define ASSERT_CTX_BUF_OFF(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, LEN)		\
	do {									\
		void *__DATA = (void *)(long)(CTX)->data;			\
		void *__DATA_END = (void *)(long)(CTX)->data_end;		\
		__DATA += OFF;							\
		bool ok = true;							\
		__u16 _len = LEN;						\
										\
		if (__DATA + (LEN) > __DATA_END) {				\
			ok = false;						\
			_len = (__u16)(__DATA_END - __DATA);			\
			test_log("CTX len (%d) - offset (%d) < LEN (%d)",	\
				 _len + OFF, OFF, LEN);				\
		}								\
		if (sizeof(BUF(BUF_NAME)) < (LEN)) {				\
			ok = false;						\
			test_log("Buffer '" #BUF_NAME "' of len (%d) < LEN"	\
				 " (%d)", sizeof(BUF(BUF_NAME)), LEN);		\
		}								\
		if (ok && memcmp(__DATA, &BUF(BUF_NAME), LEN) != 0) {		\
			ok = false;						\
			test_log("CTX and buffer '" #BUF_NAME			\
				 "' content mismatch ");			\
		}								\
		if (!ok) {							\
			hexdump_len_off(__FILE__ ":" LINE_STRING " assert '"	\
					NAME "' FAILED! Got (ctx)",		\
					FIRST_LAYER, CTX, _len, OFF);		\
			scapy_hexdump(__FILE__ ":" LINE_STRING " assert '"	\
				      NAME "' FAILED! Expected (buf)",		\
				      FIRST_LAYER, &BUF(BUF_NAME)[0],		\
				      sizeof(BUF(BUF_NAME)));			\
			test_fail_now();					\
		}								\
	} while (0)

/**
 * Compare a packet (ctx) to a scapy buffer.
 */
#define ASSERT_CTX_BUF(CTX, BUF_NAME, LEN) \
	ASSERT_CTX_BUF_OFF(CTX, 0, BUF_NAME, LEN)

static __always_inline
void scapy_hexdump(const char *msg, const char *first_layer,
		   const unsigned char *scapy_buf, const __u16 len)
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
	hex_printk("%s: pkt_hex %s[%s]", msg, first_layer, buf);
}

#include "output/gen_pkts.h"
