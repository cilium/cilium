/*
 *  Copyright (C) 2016-2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_GENEVE_H
#define __LIB_GENEVE_H

#define MAX_GENEVE_OPT_LEN 64 /* fixme support upto 252 bytes */
#define GENEVE_CLASS_EXPERIMENTAL 0xffff
#define GENEVE_TYPE_SECLABEL      1
/* This struct is passed around in the bpf program */
struct geneveopt_val {
	__u32 seclabel;
};

struct geneve_opt {
        __be16  opt_class;
        __u8      type;
#ifdef __LITTLE_ENDIAN_BITFIELD
        __u8      length:5;
        __u8      r3:1;
        __u8      r2:1;
        __u8      r1:1;
#else
        __u8      r1:1;
        __u8      r2:1;
        __u8      r3:1;
        __u8      length:5;
#endif
        __u8      opt_data[];
};

static inline int parse_geneve_options(struct geneveopt_val *val, uint8_t *buf)
{
	struct geneve_opt *opt = (struct geneve_opt *)buf;

	if (opt->opt_class != GENEVE_CLASS_EXPERIMENTAL ||
	    opt->type != GENEVE_TYPE_SECLABEL ||
	    (opt->length  << 2) != sizeof(val->seclabel))
		return DROP_INVALID_GENEVE;

	val->seclabel = ntohl(*(__u32*)opt->opt_data);
#ifdef DEBUG_GENEVE
	printk("geneve seclabel %x\n", val->seclabel);
#endif
	return 0;
}

#endif /* __LIB_GENEVE_H */
