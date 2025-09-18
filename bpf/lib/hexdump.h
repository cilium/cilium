/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>

/**
 * Reduce this if you hit complexity issues.
 * Note: Doesn't have to be a power or multiple of 2
 */
#ifndef HD_MAX_BYTES
	#define HD_MAX_BYTES 128
#endif /* HD_MAX_BYTES */

#define HD_ASCII_NUM0 '0'
#define HD_ASCII_LOWA 'a'

#define hex_printk(fmt, ...)					\
		({						\
			const char ____fmt[] = fmt;		\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})

static __always_inline
char __hexdump_nibble_to_char(__u8 nib)
{
    return nib < 10 ? (nib + HD_ASCII_NUM0) : (nib - 10 + HD_ASCII_LOWA);
}

/**
 * Dumps first len bytes (or HD_MAX_BYTES) starting at offset off
 *
 * @param first_layer First header in Scapy notation (e.g. Ether, IP, TCP...)
 */
static __always_inline
void hexdump_len_off(const char *msg, const char *first_layer,
		     const struct __ctx_buff *ctx, const __u16 len,
		     const __u8 off)
{
	__u16 i;
	char *b;
	char buf[HD_MAX_BYTES * 2 + 1] = {0};
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/**
	 * Further clamp dump len to either max of pkt or HD_MAX_BYTES
	 * and make sure it doesn't get out of the pkt boundaries
	 */
	__u16 pkt_len = (__u16)(data_end - data);
	__u16 max_dump_len = len > HD_MAX_BYTES ? HD_MAX_BYTES : len;

	max_dump_len = max_dump_len > pkt_len ? pkt_len : max_dump_len;

	if (data + off + max_dump_len > data_end)
		max_dump_len = pkt_len - off;

	for (i = 0; i < HD_MAX_BYTES; ++i) {
		if (i >= max_dump_len)
			break;

		if (data + off + i + 1 > data_end)
			break;
		b = (char *)(data + off + i);

		buf[i * 2]     = __hexdump_nibble_to_char((*b & 0xF0) >> 4);
		buf[i * 2 + 1] = __hexdump_nibble_to_char((*b & 0x0F));
	}

	hex_printk("%s: pkt_hex %s[%s]", msg, first_layer, buf);
}

/**
 * Dumps packet (or up to HD_MAX_BYTES) starting at offset off
 */
static __always_inline
void hexdump_off(const char *msg, const char *first_layer,
		 const struct __ctx_buff *ctx, const __u8 off)
{
	hexdump_len_off(msg, first_layer, ctx, HD_MAX_BYTES, off);
}

/**
 * Dump first len bytes of packet
 */
static __always_inline
void hexdump_len(const char *msg, const char *first_layer,
		 const struct __ctx_buff *ctx, const __u16 len)
{
	hexdump_len_off(msg, first_layer, ctx, len, 0);
}

/**
 * Dump entire pkt up to HD_MAX_BYTES
 */
static __always_inline
void hexdump(const char *msg, const char *first_layer,
	     const struct __ctx_buff *ctx)
{
	hexdump_len_off(msg, first_layer, ctx, HD_MAX_BYTES, 0);
}

/* Useful MACROs that prepend __FILE__:LINE_STRING */

#define HEXDUMP_LEN_OFF(MSG, FIRST_LAYER, CTX, LEN, OFF) \
	hexdump_len_off(__FILE__ ":" LINE_STRING " " MSG, #FIRST_LAYER, \
			CTX, LEN, OFF)

#define HEXDUMP_OFF(MSG, CTX, OFF) \
	hexdump_off(__FILE__ ":" LINE_STRING " " MSG, "Ether", CTX, OFF)
#define HEXDUMP_OFF2(MSG, FIRST_LAYER, CTX, OFF) \
	hexdump_off(__FILE__ ":" LINE_STRING " " MSG, #FIRST_LAYER, CTX, OFF)

#define HEXDUMP_LEN(MSG, CTX, LEN) \
	hexdump_len(__FILE__ ":" LINE_STRING " " MSG, "Ether", CTX, LEN)
#define HEXDUMP_LEN2(MSG, FIRST_LAYER, CTX, LEN) \
	hexdump_len(__FILE__ ":" LINE_STRING " " MSG, #FIRST_LAYER, CTX, LEN)

#define HEXDUMP(MSG, CTX) \
	hexdump(__FILE__ ":" LINE_STRING " " MSG, "Ether", CTX)
#define HEXDUMP2(MSG, FIRST_LAYER, CTX) \
	hexdump(__FILE__ ":" LINE_STRING " " MSG, #FIRST_LAYER, CTX)
