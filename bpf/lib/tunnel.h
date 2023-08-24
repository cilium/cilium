/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_TUNNEL_H_
#define __LIB_TUNNEL_H_

#include <linux/ipv6.h>

/* The high-order bit of the Geneve option type indicates that
 * this is a critical option.
 *
 * https://www.rfc-editor.org/rfc/rfc8926.html#name-tunnel-options
 */
#define GENEVE_OPT_TYPE_CRIT	0x80

/* Geneve option used to carry service addr and port for DSR.
 *
 * Class = 0x014B (Cilium according to [1])
 * Type  = 0x1   (vendor-specific)
 *
 * [1]: https://www.iana.org/assignments/nvo3/nvo3.xhtml#geneve-option-class
 */
#define DSR_GENEVE_OPT_CLASS	0x014B
#define DSR_GENEVE_OPT_TYPE	(GENEVE_OPT_TYPE_CRIT | 0x01)
#define DSR_IPV4_GENEVE_OPT_LEN	\
	((sizeof(struct geneve_dsr_opt4) - sizeof(struct geneve_opt_hdr)) / 4)
#define DSR_IPV6_GENEVE_OPT_LEN	\
	((sizeof(struct geneve_dsr_opt6) - sizeof(struct geneve_opt_hdr)) / 4)

struct geneve_opt_hdr {
	__be16 opt_class;
	__u8 type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 length:5,
	     rsvd:3;
#else
	__u8 rsvd:3,
	     length:5;
#endif
};

struct geneve_dsr_opt4 {
	struct geneve_opt_hdr hdr;
	__be32	addr;
	__be16	port;
	__u16	pad;
};

struct geneve_dsr_opt6 {
	struct geneve_opt_hdr hdr;
	struct in6_addr addr;
	__be16	port;
	__u16	pad;
};

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 opt_len:6,
	     ver:2;
	__u8 rsvd:6,
	     critical:1,
	     control:1;
#else
	__u8 ver:2,
	     opt_len:6;
	__u8 control:1,
	     critical:1,
	     rsvd:6;
#endif
	__be16 protocol_type;
	__u8 vni[3];
	__u8 reserved;
};

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

static __always_inline __u32
tunnel_vni_to_sec_identity(__be32 vni)
{
	return bpf_ntohl(vni) >> 8;
}

#endif /* __LIB_TUNNEL_H_ */
