// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 Authors of Cilium */

/* To compile:
 * $ clang -I../../../bpf/include -O2 -g -target bpf -emit-llvm \
 *      -Wall -Werror -Wno-address-of-packed-member             \
 *      -Wno-unknown-warning-option -c bpf_foo.c -o bpf_foo.ll
 * $ llc -march=bpf -mcpu=probe -mattr=dwarfris -filetype=obj   \
 *      -o bpf_foo.o bpf_foo.ll
 */

#include <linux/type_mapper.h>

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
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
    union {
        __u32   p1;
        __u32   p2;
    };
	__u8 family;
	__u8 pad4;
	__u16 pad5;
} __attribute__((packed));

int main() {
    __attribute__((unused)) struct foo f;

    return 0;
}
