/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

static __always_inline
__wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len)
{
	/* Unrolled loop to calculate the checksum of the ICMP sample
	 * Done manually because the compiler refuses with #pragma unroll
	 */
	__wsum wsum = 0;

	#define body(i) if ((i) > sample_len) \
		return wsum; \
	if (data_start + (i) + sizeof(__u16) > data_end) { \
		if (data_start + (i) + sizeof(__u8) <= data_end)\
			wsum += *(__u8 *)(data_start + (i)); \
		return wsum; \
	} \
	wsum += *(__u16 *)(data_start + (i));

	#define body4(i) body(i)\
		body(i + 2) \
		body(i + 4) \
		body(i + 6)

	#define body16(i) body4(i)\
		body4(i + 8) \
		body4(i + 16) \
		body4(i + 24)

	#define body128(i) body16(i)\
		body16(i + 32) \
		body16(i + 64) \
		body16(i + 96)

	body128(0)
	body128(256)
	body128(512)
	body128(768)
	body128(1024)

	return wsum;
}
