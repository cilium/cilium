/*
 *  Copyright (C) 2019 Authors of Cilium
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
