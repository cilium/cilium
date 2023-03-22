/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_TYPES_MAPPER__
#define __BPF_TYPES_MAPPER__

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long long __s64;
typedef unsigned long long __u64;

typedef __u16 __le16;
typedef __u16 __be16;

typedef __u32 __le32;
typedef __u32 __be32;

typedef __u64 __le64;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

typedef __u64 __aligned_u64;

typedef __u64 __net_cookie;
typedef __u64 __sock_cookie;

#define UINT8_MAX 0xffff

#endif /* __BPF_TYPES_MAPPER__ */
