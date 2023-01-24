/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_GENEVE__
#define __LIB_GENEVE__

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

struct geneve_opt {
	struct geneve_opt_hdr hdr;
	__u8 data[];
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
	struct geneve_opt options[];
};

#endif /* __LIB_GENEVE__ */
