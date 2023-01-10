// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

// To compile: make -C bpf testdata in repo root.

#include <linux/types.h>

union v6addr {
  struct {
    __u32 p1;
    __u32 p2;
    __u32 p3;
    __u32 p4;
  };
  __u8 addr[16];
};

struct foo {
  union {
    struct {
      __u32 ip4;
      __u32 pad1;
      __u32 pad2;
      __u32 pad3;
    };
    union v6addr ip6;
  };
  union {
    __u32 p1;
    __u32 p2;
  };
  __u8 family;
  __u8 pad4;
  __u16 pad5;
} __attribute__((packed));

struct foo _1;
union v6addr _2;
