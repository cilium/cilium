/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_MCAST_H_
#define __LIB_MCAST_H_

#include <bpf/api.h>
#include "bpf/types_mapper.h"

/* the below structures are define outside if IFDEF guard to satisfy
 * enterprise_bpf_alignchecker.c requirement
 */

/* mcast_subscriber flags */
enum {
	/* indicates subscriber is remote and ifindex is the exit interface */
	MCAST_SUB_F_REMOTE = (1U << 0)
};

/* 32bit big endian multicast group address for use with ipv4 protocol */
typedef __be32 mcast_group_v4;

/* structure to describe a local or remote subscriber of a multicast group
 * for the ipv4 protocol.
 */
struct mcast_subscriber_v4 {
	/* source address of the subscriber, big endian */
	__be32 saddr;
	/* local ifindex of subscriber of exit interface is remote subscriber */
	__u32 ifindex;
	/* reserved */
	__u16 pad1;
	/* reserved */
	__u8  pad2;
	/* flags for further subscriber description */
	__u8  flags;
};

#ifdef ENABLE_MULTICAST

#define MCAST_MAX_GROUP 1024
#define MCAST_MAX_SUBSCRIBERS 1024

/* Multicast group map is a nested hash of maps.
 * The outer map is keyed by a 'mcast_group_v4' multicast group address.
 * The inner value is an hash map of 'mcast_subscriber_v4' structures keyed
 * by a their IPv4 source address in big endian format.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, mcast_group_v4);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MCAST_MAX_GROUP);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Multicast group subscribers inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(key_size, sizeof(__be32));
		__uint(value_size, sizeof(struct mcast_subscriber_v4));
		__uint(max_entries, MCAST_MAX_SUBSCRIBERS);
		__uint(map_flags, CONDITIONAL_PREALLOC);
	});
} cilium_mcast_group_outer_v4_map __section_maps_btf;

#endif /* ENABLE_MULTICAST */
#endif /* ___LIB_MCAST_H_ */
