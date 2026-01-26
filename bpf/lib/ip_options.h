/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"

/* Max supported payload for our current storage (u64) */
#define MAX_TRACE_ID_SIZE 8

/* Maximum number of IPv4 options to process. */
#define MAX_IPV4_OPTS 3

/* The minimum value for IHL which corresponds to a packet with no options.
 *
 * A standard IP packet header has 20 bytes and the IHL is the number of 32 byte
 * words.
 */
#define IHL_WITH_NO_OPTS 5

/* Signifies that options were parsed correctly but no trace ID was found. */
#define TRACE_ID_NOT_FOUND 0

/* Signifies a failure to determine the trace ID based on an unspecified error. */
#define TRACE_ID_ERROR -1

/* Signifies that the trace ID was found but it was invalid. */
#define TRACE_ID_INVALID -2

/* Signifies a failure to determine trace ID because the IP family was not found. */
#define TRACE_ID_NO_FAMILY -3

/* Signifies a failure to determine trace ID because the IP option length was
 * not supported.
 */
#define TRACE_ID_UNSUPPORTED_LENGTH_ERROR -4

/* Signifies trace points which are being ignored because they're in IPv6
 * code and not supported yet.
 */
#define TRACE_ID_SKIP_IPV6 -100

/* trace_id_from_ip4 parses the IP options and returns the trace ID.
 *
 * See trace_id_from_ctx for more info.
 */
static __always_inline int
trace_id_from_ip4(struct __ctx_buff *ctx, __s64 *value,
		  const struct iphdr *ip4,
		  __u8 trace_ip_opt_type)
{
	__u8 opt_type;
	__u32 offset;
	__u8 optlen;
	__u32 end;
	int i;

	if (ip4->ihl <= IHL_WITH_NO_OPTS)
		return TRACE_ID_NOT_FOUND;

	offset = ETH_HLEN + sizeof(struct iphdr);
	end = offset + (ip4->ihl << 2);

#pragma unroll(MAX_IPV4_OPTS)
	for (i = 0; i < MAX_IPV4_OPTS && offset < end; i++) {
		/* 1. Load Option Type */
		if (ctx_load_bytes(ctx, offset, &opt_type, 1) < 0)
			return TRACE_ID_ERROR;

		if (opt_type == IPOPT_END) break;
		if (opt_type == IPOPT_NOOP) {
			offset++;
			continue;
		}

		/* 2. Load Option Length */
		if (ctx_load_bytes(ctx, offset + 1, &optlen, 1) < 0)
			return TRACE_ID_ERROR;

		/* Standard sanity check: Length includes Type(1) + Len(1) = 2 bytes min */
		if (optlen < 2)
			return TRACE_ID_INVALID;

		if (opt_type != trace_ip_opt_type) {
			offset += optlen;
			continue;
		}

		/* Calculate actual payload size */
		__u8 payload_len = optlen - 2;

		/* If payload is 0, we found the tag but it's empty. Return 0. */
		if (payload_len == 0) {
			*value = 0;
			return 0;
		}

		__u8 read_len = payload_len;

		if (read_len > MAX_TRACE_ID_SIZE)
			read_len = MAX_TRACE_ID_SIZE;

		__u64 accumulator = 0;

		#pragma unroll
		for (int j = 0; j < MAX_TRACE_ID_SIZE; j++) {
			if (j < read_len) {
				__u8 byte;
				/* Load byte: offset + Type(1) + Len(1) + Index(j) */
				if (ctx_load_bytes(ctx, offset + 2 + j, &byte, 1) < 0)
					return TRACE_ID_ERROR;

				/* Shift left and add new byte (Big Endian construction) */
				accumulator = (accumulator << 8) | byte;
			}
		}

		/* Cast back to __s64 as required by the function signature */
		*value = (__s64)accumulator;
		return 0;
	}
	return TRACE_ID_NOT_FOUND;
}

/*
 * Parses the context to extract the trace ID from the IP options.
 *
 * Arguments:
 * - ctx: The context buffer from which the IP options will be read.
 * - value: A pointer to an __s64 where the resulting trace ID will be stored.
 * - ip_opt_type_value: The type value of the IP option that contains the trace ID.
 *
 * Prerequisites:
 * - Supports reading a trace ID embedded in IP options with lengths of 2, 4, or 8 bytes.
 * - No support for trace_ids that are not 2, 4, or 8 bytes.
 *
 * Outputs:
 * - Returns 0 if the trace ID is found.
 * - Returns TRACE_ID_NOT_FOUND if no trace ID is found in the options.
 * - Returns TRACE_ID_INVALID if the found trace ID is invalid (e.g., non-positive).
 * - Returns TRACE_ID_ERROR if there is an error during parsing.
 * - Returns TRACE_ID_NO_FAMILY if the packet is not IPv4.
 * - Returns TRACE_ID_SKIP_IPV6 if the packet is IPv6.
 */
static __always_inline int
trace_id_from_ctx(struct __ctx_buff *ctx, __s64 *value, __u8 ip_opt_type_value)
{
	void *data, *data_end;
	__s64 trace_id = 0;
	struct iphdr *ip4;
	__be16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto))
		return TRACE_ID_ERROR;

	if (proto == bpf_htons(ETH_P_IPV6))
		return TRACE_ID_SKIP_IPV6;

	if (proto != bpf_htons(ETH_P_IP))
		return TRACE_ID_NO_FAMILY;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return TRACE_ID_ERROR;

	ret = trace_id_from_ip4(ctx, &trace_id, ip4, ip_opt_type_value);
	if (IS_ERR(ret))
		return ret;

	*value = trace_id;
	return 0;
}
