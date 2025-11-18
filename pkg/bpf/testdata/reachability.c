#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

/* Emit a symbol sentinel and an access to it. Can be checked using
 * asm.Instruction.Reference(). */
#define SYMBOL(name) { void * name; asm volatile("%0 = " __stringify(name) :"=r"(name)); }

DECLARE_CONFIG(bool, sym_a, "Make sym_a reachable")
DECLARE_CONFIG(__u64, sym_b, "Make sym_b reachable if value >= max uint32, requiring 64-bit reg-reg comparison")
DECLARE_CONFIG(struct { __u8 _pad; bool sym_c; __u32 sym_d; }, sym_cd, "Make sym_c and sym_d reachable")
DECLARE_CONFIG(__s64, sym_e, "Make sym_e reachable if value is negative")
DECLARE_CONFIG(__s8, sym_f, "Make sym_f reachable if value is negative, testing sign extension")
DECLARE_CONFIG(__s16, sym_g, "Make sym_g reachable if value is negative, testing sign extension")
DECLARE_CONFIG(__s32, sym_h, "Make sym_h reachable if value is negative, testing sign extension")
DECLARE_CONFIG(bool, sym_i, "Make sym_i reachable")
DECLARE_CONFIG(bool, sym_j, "Make sym_j reachable")
DECLARE_CONFIG(__s16, sym_k, "Make sym_k reachable if bit 1 is set")
DECLARE_CONFIG(__u32, sym_l, "Make sym_l reachable if bit 1 is set")

__noinline
void func_i() {
        SYMBOL(sym_i);
}

__noinline
void func_j() {
        if CONFIG(sym_j) {
                SYMBOL(sym_j);
        }
}

__section("tc")
static int entry() {
        if (CONFIG(sym_a))
                SYMBOL(sym_a);

        if (CONFIG(sym_b) >= 1LL<<32)
                SYMBOL(sym_b);

        if (CONFIG(sym_cd).sym_c)
                SYMBOL(sym_c);

        if (CONFIG(sym_cd).sym_d == 1234)
                SYMBOL(sym_d);

        if (CONFIG(sym_e) < 0)
                SYMBOL(sym_e);

        if (CONFIG(sym_f) < 0)
                SYMBOL(sym_f);

        if (CONFIG(sym_g) < 0)
                SYMBOL(sym_g);

        if (CONFIG(sym_h) < 0)
                SYMBOL(sym_h);

        if (CONFIG(sym_i))
                func_i();

        func_j();

        if (CONFIG(sym_k) & 1)
                SYMBOL(sym_k);

        if (CONFIG(sym_l) & 1)
                SYMBOL(sym_l);

        return 0;
}
