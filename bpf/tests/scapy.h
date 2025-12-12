/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "../lib/hexdump.h"

#define __SCAPY_MAX_BUF (1518)
#define __SCAPY_MAX_STR_LEN 128
#define __SCAPY_MAX_ASSERTS 256

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
void scapy_strncpy(char *dst, const char *src, const __u8 len)
{
	if (len > __SCAPY_MAX_STR_LEN)
		return;
	scapy_memcpy(dst, src, len);
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
 * Assert structure to store in the map
 */
struct scapy_assert {
	char name[__SCAPY_MAX_STR_LEN];		/* Assert name */
	char file[__SCAPY_MAX_STR_LEN];		/* Filename */
	char lnum[__SCAPY_MAX_STR_LEN];		/* Line number */
	char first_layer[__SCAPY_MAX_STR_LEN];	/* Scapy  layer (e.g. Ether) */
	__u16 exp_len;				/* Exp. len (compared len) */
	__u8 exp_buf[__SCAPY_MAX_BUF];		/* Expected buffer */
	__u16 got_len;				/* Got buffer len */
	__u8 got_buf[__SCAPY_MAX_BUF];		/* Got buffer */
	__u8 pad[2];
};

/**
 * Map providing scapy assert storage
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct scapy_assert));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, __SCAPY_MAX_ASSERTS);
} scapy_assert_map __section_maps_btf;
static __u32 scapy_assert_map_cnt;

/* Needs to be here not to blow up stack size */
static struct scapy_assert __scapy_assert = {0};
static struct scapy_assert __scapy_null_assert = {0};

#ifndef __ASSERT_TRACE_FAIL_LEN
#define __ASSERT_TRACE_FAIL_LEN(BUF_NAME, _BUF_LEN, LEN)		\
	test_log("Buffer '" BUF_NAME "' of len (%d) < LEN  (%d)",	\
			 _BUF_LEN, LEN)
#endif /* __ASSERT_TRACE_FAIL_LEN */

#ifndef __ASSERT_TRACE_FAIL_BUF
#define __ASSERT_TRACE_FAIL_BUF(BUF_NAME, _BUF_LEN, LEN)		\
	test_log("CTX and buffer '" BUF_NAME "' content mismatch ")
#endif /* __ASSERT_TRACE_FAIL_BUF */

#define __SCAPY_GET_CTX_LEN(__DATA, __DATA_END) \
	(__u16)((unsigned long long)(__DATA_END) - (unsigned long long)(__DATA))

static __always_inline
bool __assert_map_add_failure(const char *name, const __u8 name_len,
			      const char *first_layer,
			      const __u8 first_layer_len,
			      const unsigned char *buf,
			      const __u16 len, void *data,
			      const void *data_end)
{
	__scapy_assert.exp_len = len;
	scapy_memcpy(__scapy_assert.exp_buf, buf, len);

	__scapy_assert.got_len = __SCAPY_GET_CTX_LEN(data, data_end);
	if (data + len <= data_end) {
		scapy_memcpy(__scapy_assert.got_buf, data, len);
	} else {
		/* Clear previous assert content */
		scapy_memcpy(__scapy_assert.got_buf,
			     __scapy_null_assert.got_buf, len);
	}

	scapy_strncpy(__scapy_assert.name, name, name_len);
	scapy_strncpy(__scapy_assert.file, __FILE__, sizeof(__FILE__));
	scapy_strncpy(__scapy_assert.lnum, LINE_STRING, sizeof(LINE_STRING));
	scapy_strncpy(__scapy_assert.first_layer, first_layer, first_layer_len);

	return map_update_elem(&scapy_assert_map, &scapy_assert_map_cnt,
			    &__scapy_assert, BPF_ANY) == 0;
}

#define __ASSERT_CTX_BUF_OFF(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, _BUF,		\
			    _BUF_LEN, LEN)						\
	do {										\
		void *__DATA = (void *)(long)(CTX)->data;				\
		void *__DATA_END = (void *)(long)(CTX)->data_end;			\
		__DATA += OFF;								\
		bool _ok = true;							\
		__u16 _len = LEN;							\
											\
		if (__DATA + (LEN) > __DATA_END) {					\
			_ok = false;							\
			test_log("CTX len (%d) - offset (%d) < LEN (%d)",		\
					 _len + OFF, OFF, LEN);				\
		}									\
		if ((_BUF_LEN) < (LEN)) {						\
			_ok = false;							\
			__ASSERT_TRACE_FAIL_LEN(BUF_NAME, _BUF_LEN, LEN);		\
		}									\
		if (_ok && scapy_memcmp(__DATA, _BUF, LEN) != 0) {			\
			_ok = false;							\
			__ASSERT_TRACE_FAIL_BUF(BUF_NAME, _BUF_LEN, LEN);		\
		}									\
		if (!_ok) {								\
			if (!__assert_map_add_failure(NAME, sizeof(NAME),		\
						      FIRST_LAYER,			\
						      sizeof(FIRST_LAYER),		\
						      _BUF, LEN, __DATA,		\
						      __DATA_END)) {			\
				test_log("ERROR: unable to push failed assert to map!");\
				test_fail_now();					\
			}								\
			++scapy_assert_map_cnt;						\
			test_fail_now();						\
		}									\
	} while (0)

/**
 * Compare a packet (ctx) to a scapy buffer(BUF_NAME) starting from ctx's OFF
 * byte. As opposed ASSERT_CTX_BUF_OFF, this version receives a pointer to
 * the buffer _BUF and the _BUF_LEN.
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
#define ASSERT_CTX_BUF_OFF2(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, _BUF,	\
			    _BUF_LEN, LEN)					\
	__ASSERT_CTX_BUF_OFF(NAME, FIRST_LAYER, CTX, OFF, BUF_NAME, _BUF,	\
			     _BUF_LEN, LEN)

/**
 * Compare a packet (ctx) to a scapy buffer(BUF_NAME) starting from ctx's OFF
 * byte.
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

#include "output/gen_pkts.h"
