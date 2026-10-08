/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"

/* Length of the initial supported IPv4 trace_id option (4 bytes).
 * IPv4 IP options consist of 2 fixed bytes for the type and length,
 * followed by a variable-length data field. An option length of 4 bytes
 * indicates 2 fixed bytes for the type and length fields, and 2 bytes of
 * ip_trace_id data.
 */
#define OPT16_LEN 4

/* Length of the second supported IPv4 trace_id option (6 bytes).
 * Indicates 4 bytes of ip_trace_id data.
 */
#define OPT32_LEN 6

/* Length of the third supported IPv4 trace_id option (10 bytes).
 * Indicates 8 bytes of ip_trace_id data.
 */
#define OPT64_LEN 10

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
		/* We load the option header 1 field at a time since different types
		 * have different formats.
		 *
		 * "Options 0 and 1 are exactly one octet which is their type field. All
		 * other options have their one octet type field, followed by a one
		 * octet length field, followed by length-2 octets of option data."
		 *
		 * Ref: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
		 */

		if (ctx_load_bytes(ctx, offset, &opt_type, 1) < 0)
			return TRACE_ID_ERROR;

		if (opt_type == IPOPT_END)
			break;

		if (opt_type == IPOPT_NOOP) {
			offset++;
			continue;
		}

		if (ctx_load_bytes(ctx, offset + 1, &optlen, 1) < 0)
			return TRACE_ID_ERROR;

		if (opt_type != trace_ip_opt_type) {
			offset += optlen;
			continue;
		}

		if (optlen != OPT16_LEN && optlen != OPT32_LEN && optlen != OPT64_LEN)
			return TRACE_ID_INVALID;

		switch (optlen) {
			case OPT16_LEN: {
				__s16 temp;

				if (ctx_load_bytes(ctx, offset + 2, &temp, sizeof(temp)) < 0)
					return TRACE_ID_ERROR;
				*value = bpf_ntohs(temp);
				return 0;
			}
			case OPT32_LEN: {
				__s32 temp;

				if (ctx_load_bytes(ctx, offset + 2, &temp, sizeof(temp)) < 0)
					return TRACE_ID_ERROR;
				*value = bpf_ntohl(temp);
				return 0;
			}
			case OPT64_LEN: {
				__s64 temp;

				if (ctx_load_bytes(ctx, offset + 2, &temp, sizeof(temp)) < 0)
					return TRACE_ID_ERROR;
				*value = __bpf_be64_to_cpu(temp);
				return 0;
			}
		default:
			return TRACE_ID_UNSUPPORTED_LENGTH_ERROR;
		}
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
