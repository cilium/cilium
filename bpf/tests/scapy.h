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
	const unsigned char BUF(NAME)[] = __SCAPY_BUF_BYTES(NAME)

static __always_inline
int scapy_memcmp(const void *a, const void *b, const __u16 len)
{
	__u32 i;

	for (i = 0; i + 8 <= len; i += 8) {
		__u64 va = *(__u64 *)(a + i);
		__u64 vb = *(__u64 *)(b + i);

		if (va != vb)
			return (va < vb) ? -1 : 1;
	}

	#pragma unroll
	for (; i < len; i++) {
		__u8 va = *(__u8 *)(a + i);
		__u8 vb = *(__u8 *)(b + i);

		if (va != vb)
			return (va < vb) ? -1 : 1;
	}

	return 0;
}

static __always_inline
void scapy_memcpy(const void *dst, const void *src, const __u32 len)
{
	__u32 i;

	#pragma unroll
	for (i = 0; i + 8 <= len; i += 8)
		*(__u64 *)(dst + i) = *(__u64 *)(src + i);

	#pragma unroll
	for (; i < len; i++)
		*(__u8 *)(dst + i) = *(__u8 *)(src + i);
}

static __always_inline
void *scapy__push_data(struct pktgen *builder, void *data, int len)
{
	void *pkt_data = pktgen__push_data_room(builder, len);

	if (!pkt_data)
		return 0;
	if (pkt_data + len > ctx_data_end(builder->ctx))
		return 0;

	scapy_memcpy(pkt_data, data, len);

	return pkt_data;
}

/**
 * Push (append) BUF(NAME) to the end of the ctx pkt builder.
 */
#define BUILDER_PUSH_BUF(BUILDER, NAME)					\
	do {								\
		if (!scapy__push_data(&(BUILDER), (void *)&BUF(NAME),	\
				       sizeof(BUF(NAME))))		\
			return TEST_ERROR;				\
	} while (0)

/**
 * Compare a packet (ctx) to a scapy buffer starting from ctx's OFF byte
 *
 * NAME: assertion quoted name (unique in the test): "test_a".
 * FIRST_LAYER: Scapy layer name (e.g. Ether, IP), quoted: "Ether".
 * CTX: ctx ptr.
 * OFF: start to compare against ctx->data + OFF.
 * BUF_NAME: scapy buffer name (quoted literal)
 * _BUF: pointer to the first byte of the scapy buffer BUF_DECL() / BUF().
 * _BUF_LEN: length of the buffer.
 * LEN: how many bytes to compare.
 */
#define ASSERT_CTX_BUF_OFF2(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, _BUF,		\
			    _BUF_LEN, LEN)						\
	do {										\
		void *__DATA = (void *)(long)(CTX)->data;				\
		void *__DATA_END = (void *)(long)(CTX)->data_end;			\
		__DATA += OFF;								\
		bool ok = true;								\
		__u16 _len = LEN;							\
											\
		if (__DATA + (LEN) > __DATA_END) {					\
			ok = false;							\
			_len = (__u16)(__DATA_END - __DATA);				\
			test_log("CTX len (%d) - offset (%d) < LEN (%d)",		\
				 _len + OFF, OFF, LEN);					\
		}									\
		if ((_BUF_LEN) < (LEN)) {						\
			ok = false;							\
			test_log("Buffer '" BUF_NAME "' of len (%d) < LEN  (%d)",	\
				 _BUF_LEN, LEN);					\
		}									\
		if (ok && scapy_memcmp(__DATA, _BUF, LEN) != 0) {			\
			ok = false;							\
			test_log("CTX and buffer '" BUF_NAME "' content mismatch ");	\
		}									\
		if (!ok) {								\
			hexdump_len_off(__FILE__ ":" LINE_STRING " assert '"		\
					NAME "' FAILED! Got (ctx)",			\
					FIRST_LAYER, CTX, _len, OFF);			\
			scapy_hexdump(__FILE__ ":" LINE_STRING " assert '"		\
				      NAME "' FAILED! Expected (buf)",			\
				      FIRST_LAYER, _BUF, _BUF_LEN);			\
			test_fail_now();						\
		}									\
	} while (0)

/**
 * Compare a packet (ctx) to a scapy buffer starting from ctx's OFF byte
 *
 * NAME: assertion quoted name (unique in the test): "test_a".
 * FIRST_LAYER: Scapy layer name (e.g. Ether, IP), quoted: "Ether".
 * CTX: ctx ptr.
 * BUF_NAME: scapy buffer name (string)
 * LEN: how many bytes to compare.
 */
#define ASSERT_CTX_BUF_OFF(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, LEN)		\
	{									\
		ASSERT_CTX_BUF_OFF2(NAME, FIRST_LAYER, CTX, OFF,		\
				    #BUF_NAME, BUF(BUF_NAME),			\
				    sizeof(BUF(BUF_NAME)), LEN);		\
	} do {} while (0)

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
