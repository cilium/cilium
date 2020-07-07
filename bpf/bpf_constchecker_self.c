// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Authors of Cilium */

#include <bpf/types_mapper.h>

const __u8  foo_const   = 23;
const __u16 ignore_1    = 0x0a;
const __u8  ignore_2    = 0x0b;
const __u32 ignore_3    = 0x0c;
const __u8  ignore_4    = 0x0d;
const __u64 bar_const   = 12345678;
