/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Base capture notifications version.
 * Must be incremented when the format of NOTIFY_CAPTURE_HDR changes.
 *
 * Individual notify messages may evolve independently, specifying their own versions.
 */
#define NOTIFY_CAPTURE_VER 1

enum {
	CILIUM_NOTIFY_UNSPEC,
	CILIUM_NOTIFY_DROP,
	CILIUM_NOTIFY_DBG_MSG,
	CILIUM_NOTIFY_DBG_CAPTURE,
	CILIUM_NOTIFY_TRACE,
	CILIUM_NOTIFY_POLICY_VERDICT,
	CILIUM_NOTIFY_CAPTURE,
	CILIUM_NOTIFY_TRACE_SOCK,
};

#define NOTIFY_COMMON_HDR \
	__u8		type;		\
	__u8		subtype;	\
	__u16		source;		\
	__u32		hash;

#define NOTIFY_CAPTURE_HDR \
	NOTIFY_COMMON_HDR						\
	__u32		len_orig;	/* Length of original packet */	\
	__u16		len_cap;	/* Length of captured bytes */	\
	__u16		version;	/* Capture header version */

#define __notify_common_hdr(t, s)	\
	.type		= (t),		\
	.subtype	= (s),		\
	.source		= EVENT_SOURCE,	\
	.hash		= get_hash(ctx)   /* Avoids hash recalculation, assumes hash has been already calculated */

#define __notify_pktcap_hdr(o, c, v)	\
	.len_orig	= (o),		\
	.len_cap	= (c),		\
	.version	= (v)

