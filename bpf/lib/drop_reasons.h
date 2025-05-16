/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Cilium error codes, must NOT overlap with TC return codes.
 * These also serve as drop reasons for metrics,
 * where reason > 0 corresponds to -(DROP_*)
 *
 * These are shared with pkg/monitor/api/drop.go and api/v1/flow/flow.proto.
 * When modifying any of the below, those files should also be updated.
 */
#define DROP_UNUSED1		-130 /* unused */
#define DROP_UNUSED2		-131 /* unused */
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_FRAG_NEEDED	-136
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_UNUSED4		-138 /* unused */
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP4_CODE	-143
#define DROP_UNKNOWN_ICMP4_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_UNUSED5		-148 /* unused */
#define DROP_UNUSED6		-149 /* unused */
#define DROP_UNKNOWN_TARGET	-150
#define DROP_UNROUTABLE		-151
#define DROP_UNUSED7		-152 /* unused */
#define DROP_CSUM_L3		-153
#define DROP_CSUM_L4		-154
#define DROP_CT_CREATE_FAILED	-155
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157
#define DROP_NO_SERVICE		-158
#define DROP_UNSUPP_SERVICE_PROTO	-159
#define DROP_NO_TUNNEL_ENDPOINT -160
#define DROP_NAT_46X64_DISABLED	-161
#define DROP_EDT_HORIZON	-162
#define DROP_UNKNOWN_CT		-163
#define DROP_HOST_UNREACHABLE	-164
#define DROP_NO_CONFIG		-165
#define DROP_UNSUPPORTED_L2	-166
#define DROP_NAT_NO_MAPPING	-167
#define DROP_NAT_UNSUPP_PROTO	-168
#define DROP_NO_FIB		-169
#define DROP_ENCAP_PROHIBITED	-170
#define DROP_INVALID_IDENTITY	-171
#define DROP_UNKNOWN_SENDER	-172
#define DROP_NAT_NOT_NEEDED	-173 /* Mapped as drop code, though drop not necessary. */
#define DROP_IS_CLUSTER_IP	-174
#define DROP_FRAG_NOT_FOUND	-175
#define DROP_FORBIDDEN_ICMP6	-176
#define DROP_NOT_IN_SRC_RANGE	-177
#define DROP_PROXY_LOOKUP_FAILED	-178
#define DROP_PROXY_SET_FAILED	-179
#define DROP_PROXY_UNKNOWN_PROTO	-180
#define DROP_POLICY_DENY	-181
#define DROP_VLAN_FILTERED	-182
#define DROP_INVALID_VNI	-183
#define DROP_INVALID_TC_BUFFER  -184
#define DROP_NO_SID		-185
#define DROP_MISSING_SRV6_STATE	-186 /* unused */
#define DROP_NAT46		-187
#define DROP_NAT64		-188
#define DROP_POLICY_AUTH_REQUIRED	-189
#define DROP_CT_NO_MAP_FOUND	-190
#define DROP_SNAT_NO_MAP_FOUND	-191
#define DROP_INVALID_CLUSTER_ID	-192
#define DROP_DSR_ENCAP_UNSUPP_PROTO	-193
#define DROP_NO_EGRESS_GATEWAY	-194
#define DROP_UNENCRYPTED_TRAFFIC	-195
#define DROP_TTL_EXCEEDED	-196
#define DROP_NO_NODE_ID		-197
#define DROP_RATE_LIMITED	-198
#define DROP_IGMP_HANDLED	-199
#define DROP_IGMP_SUBSCRIBED    -200
#define DROP_MULTICAST_HANDLED  -201
#define DROP_HOST_NOT_READY	-202
#define DROP_EP_NOT_READY	-203
#define DROP_NO_EGRESS_IP	-204
#define DROP_PUNT_PROXY		-205 /* Mapped as drop code, though drop not necessary. */
