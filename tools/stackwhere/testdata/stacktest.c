// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <bpf/compiler.h>

// The object file should produce the following output:
// go run tools/stackwhere/main.go --call-stack tools/stackwhere/testdata/stacktest.o cil_entry
// R10-48:
//   8 - one_inlined_d @ tools/stackwhere/testdata/stacktest.c:51
//     inlined_d @ tools/stackwhere/testdata/stacktest.c:50
//     inlined_c @ tools/stackwhere/testdata/stacktest.c:55
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
// R10-32:
//   16 - two_inlined_a @ tools/stackwhere/testdata/stacktest.c:70
//     inlined_a @ tools/stackwhere/testdata/stacktest.c:69
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
//   16 - two_inlined_b @ tools/stackwhere/testdata/stacktest.c:65
//     inlined_b @ tools/stackwhere/testdata/stacktest.c:64
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
//   16 - two_inlined_c @ tools/stackwhere/testdata/stacktest.c:56
//     inlined_c @ tools/stackwhere/testdata/stacktest.c:55
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
// R10-0:
//   32 - a @ tools/stackwhere/testdata/stacktest.c:81
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
//   32 - b @ tools/stackwhere/testdata/stacktest.c:91
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75
//   32 - c @ tools/stackwhere/testdata/stacktest.c:99
//     cil_entry @ tools/stackwhere/testdata/stacktest.c:75

struct four {
        unsigned long long a;
        unsigned long long b;
        unsigned long long c;
        unsigned long long d;
};

struct two {
        unsigned long long a;
        unsigned long long b;
};

// An ASM block, with no actual instructions, but we tell the compiler that we need to have the
// address of x in a register. And the only way to get the address of x is to put it on the stack.
// This forces the compiler to put x on the stack, even if it could have otherwise optimized it away
// or kept it in registers.
#define force_on_stack(x) asm volatile("" ::"r"(&x))

void __always_inline inlined_d() {
        unsigned long long one_inlined_d = 0;
        force_on_stack(one_inlined_d);
}

void __always_inline inlined_c() {
        struct two two_inlined_c = {};
        force_on_stack(two_inlined_c);
        // `two_inlined_c` is never used after this point, but `inlined_d` will use a new stack slot
        // anyway because the "lifetime" of `two_inlined_c` ends at the end of the function.
        // So the compiler will use more stack space here then technically needed.
        inlined_d();
}

void __always_inline inlined_b() {
        struct two two_inlined_b = {};
        force_on_stack(two_inlined_b);
}

void __always_inline inlined_a() {
        struct two two_inlined_a = {};
        force_on_stack(two_inlined_a);
}

__section("tc")
int cil_entry(struct __sk_buff *ctx)
{
        {
                // a will live on the stack until the end of the scope, so inlined_a and inlined_b
                // cannot reuse its stack space. But inlined_b can reused the stack space of 
                // inlined_a.
                struct four a = {};
                force_on_stack(a);
                inlined_a();
                inlined_b();
        }

        // Variables in this scope can reuse the stack space of a, inlined_a, and inlined_b.
        // So `b`, `two_inlined_a` and `two_inlined_b` will be placed on the same stack slots as
        // those used above.
        {
                struct four b = {};
                force_on_stack(b);
                inlined_a();
                inlined_b();
        }

        // `c` will fit over stack used by `a` and `b`.
        {
                struct four c = {};
                force_on_stack(c);
                // `inlined_c` calls `inlined_d` before the end of its function, and thus `inlined_d`
                // will use an additional stack slot.
                inlined_c();
        }
        return 0;
}
